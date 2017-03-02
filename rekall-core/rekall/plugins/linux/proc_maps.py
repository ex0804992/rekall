# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""
from rekall import testlib
from rekall import utils
from rekall.plugins import core
from rekall.plugins.addrspaces import intel
from rekall.plugins.common import pfn
from rekall.plugins.linux import common
import hashlib

class ProcMaps(common.LinProcessFilter):
    """Gathers process maps for linux."""

    __name = "maps"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="task", hidden=True),
        dict(name="start", style="address"),
        dict(name="end", style="address"),
        dict(name="flags", width=6),
        dict(name="pgoff", style="address"),
        dict(name="major", width=6),
        dict(name="minor", width=6),
        dict(name="inode", width=13),
        dict(name="file_path"),
    ]


    def collect(self):
        for task in self.filter_processes():
            if not task.mm:
                continue

            yield dict(divider="Proc %s (%s)" % (task.name, task.pid))

            for vma in task.mm.mmap.walk_list("vm_next"):
                if vma.vm_file:
                    inode = vma.vm_file.dentry.d_inode
                    major, minor = inode.i_sb.major, inode.i_sb.minor
                    ino = inode.i_ino
                    pgoff = vma.vm_pgoff << 12
                    fname = task.get_path(vma.vm_file)
                else:
                    (major, minor, ino, pgoff) = [0] * 4

                    if (vma.vm_start <= task.mm.start_brk and
                            vma.vm_end >= task.mm.brk):
                        fname = "[heap]"
                    elif (vma.vm_start <= task.mm.start_stack and
                          vma.vm_end >= task.mm.start_stack):
                        fname = "[stack]"
                    else:
                        fname = ""

                yield dict(task=task,
                           start=vma.vm_start,
                           end=vma.vm_end,
                           flags=vma.vm_flags,
                           pgoff=pgoff,
                           major=major,
                           minor=minor,
                           inode=ino,
                           file_path=fname)


class TestProcMaps(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="maps --proc_regex %(proc_name)s",
        proc_name="bash"
        )


class LinVadDump(core.DirectoryDumperMixin, common.LinProcessFilter):
    """Dump the VMA memory for a process."""

    __name = "vaddump"

    def render(self, renderer):
        for task in self.filter_processes():
            if not task.mm:
                continue

            renderer.format("Pid: {0:6}\n", task.pid)

            # Get the task and all process specific information
            task_space = task.get_process_address_space()
            name = task.comm

            for vma in task.mm.mmap.walk_list("vm_next"):
                if not vma.vm_file:
                    continue

                filename = "{0}.{1}.{2:08x}-{3:08x}.dmp".format(
                    name, task.pid, vma.vm_start, vma.vm_end)

                renderer.format(u"Writing {0}, pid {1} to {2}\n",
                                task.comm, task.pid, filename)

                with renderer.open(directory=self.dump_dir,
                                   filename=filename,
                                   mode='wb') as fd:
                    self.CopyToFile(task_space, vma.vm_start, vma.vm_end, fd)

class LinHashMemPage(core.DirectoryDumperMixin, common.LinProcessFilter):
    """Hash the given memory page for a process."""

    __name = "hashmempage"

    __args = [
        dict(name="guestvirtaddr", type="IntParser",
            help="A guest virtual address."),
    ]

    def render(self, renderer):
        for task in self.filter_processes():
            if not task.mm:
                continue

            renderer.format("Pid: {0:6}\n", task.pid)

            # Get the task and all process specific information
            task_space = task.get_process_address_space()
            name = task.comm

            for vma in task.mm.mmap.walk_list("vm_next"):
#                if not vma.vm_file:
#                    continue

                # Skip the entire region.
                if vma.vm_end < self.plugin_args.guestvirtaddr:
                    continue
                if vma.vm_start > self.plugin_args.guestvirtaddr:
                    continue

                BUFFSIZE = 1024 * 1024
                addr = self.plugin_args.guestvirtaddr
                renderer.format(u"Given virtual address : {0}\n", hex(addr))
                start = addr - (addr & 0xfff)
                end = start + 0x1000

                filename = "{0}.{1}.{2:08x}-{3:08x}".format(
                    name, task.pid, start, end)
                renderer.format(u"Hash {0}\n", filename)

                for run in task_space.get_address_ranges(start=start, end=end):
                    out_offset = run.start - start
#                    renderer.format(u"Dumping {0} Mb\n", out_offset / BUFFSIZE)
                    i = run.start

                    # Now copy the region in fixed size buffers.
                    while i < run.end:
                        to_read = min(BUFFSIZE, run.end - i)

                        renderer.format(u"read : {0}~{1}\n", hex(run.start), hex(run.end))
                        #data = task_space.read(i, to_read)
                        data = task_space.read(i, 4096)

                        md5 = hashlib.md5()
                        md5_local = md5.copy()
                        md5_local.update(data)
                        checksum = md5_local.hexdigest()
                        renderer.format(u"checksum of name : {0}\n", checksum)

                        with renderer.open(directory=self.dump_dir,
                                           filename="test.dmp",
                                           mode='wb') as fd:
                            fd.write(data)
                        i += to_read

class TestLinVadDump(testlib.HashChecker):
    mode = "mode_linux_memory"

    PARAMETERS = dict(
        commandline="vaddump --proc_regex %(proc_name)s --dump_dir %(tempdir)s",
        proc_name="bash"
        )



class LinuxVADMap(pfn.VADMapMixin, common.LinProcessFilter):
    """Inspect each page in the VAD and report its status.

    This allows us to see the address translation status of each page in the
    VAD.
    """

    def _CreateMetadata(self, collection):
        metadata = {}
        for descriptor_cls, args, kwargs in reversed(collection.descriptors):
            if issubclass(descriptor_cls, intel.PhysicalAddressDescriptor):
                metadata["offset"] = kwargs["address"]
                metadata.setdefault("type", "Valid")

            elif issubclass(descriptor_cls, intel.InvalidAddress):
                metadata["type"] = "Invalid"

        return metadata

    def GeneratePageMetatadata(self, task):
        address_space = self.session.GetParameter("default_address_space")

        for vma in task.mm.mmap.walk_list("vm_next"):
            start = vma.vm_start
            end = vma.vm_end

            # Skip the entire region.
            if end < self.plugin_args.start:
                continue

            # Done.
            if start > self.plugin_args.end:
                break

            for vaddr in utils.xrange(start, end, 0x1000):
                if self.plugin_args.start <= vaddr <= self.plugin_args.end:
                    yield vaddr, self._CreateMetadata(
                        address_space.describe_vtop(vaddr))
