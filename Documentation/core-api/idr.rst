.. SPDX-License-Identifier: GPL-2.0+

=============
ID Allocation
=============

:Author: Matthew Wilcox

Overview
========

A common problem to solve is allocating identifiers (IDs); generally
small numbers which identify a thing.  Examples include file descriptors,
process IDs, packet identifiers in networking protocols, SCSI tags
and device instance numbers.  The IDR and the IDA provide a reasonable
solution to the problem to avoid everybody inventing their own.  The IDR
provides the ability to map an ID to a pointer, while the IDA provides
only ID allocation, and as a result is much more memory-efficient.

IDR usage       (map: id -> pointer)
=========

Start by initialising an IDR, either with DEFINE_IDR()                  _初始化_
for statically allocated IDRs or idr_init() for dynamically
allocated IDRs.

You can call idr_alloc() to allocate an unused ID.  Look up             _分配 unused ID_
the pointer you associated with the ID by calling idr_find()            _用 id 索引指针 idr_find()_
and free the ID by calling idr_remove().                                _释放 idr_remove()_

If you need to change the pointer associated with an ID, you can call
idr_replace().  One common reason to do this is to reserve an           _修改指针 idr_replace()_
ID by passing a ``NULL`` pointer to the allocation function; initialise the
object with the reserved ID and finally insert the initialised object
into the IDR.

Some users need to allocate IDs larger than ``INT_MAX``.  So far all of
these users have been content with a ``UINT_MAX`` limit, and they use
idr_alloc_u32().  If you need IDs that will not fit in a u32,
we will work with you to address your needs.

If you need to allocate IDs sequentially, you can use                   _按照顺序分配 idr_alloc_cyclic()_
idr_alloc_cyclic().  The IDR becomes less efficient when dealing
with larger IDs, so using this function comes at a slight cost.

To perform an action on all pointers used by the IDR, you can           _idr_for_each() 迭代所有 id_
either use the callback-based idr_for_each() or the
iterator-style idr_for_each_entry().  You may need to use
idr_for_each_entry_continue() to continue an iteration.  You can
also use idr_get_next() if the iterator doesn't fit your needs.

When you have finished using an IDR, you can call idr_destroy()         _idr_destroy() 销毁一个 idr_
to release the memory used by the IDR.  This will not free the objects
pointed to from the IDR; if you want to do that, use one of the iterators
to do it.

You can use idr_is_empty() to find out whether there are any
IDs currently allocated.

If you need to take a lock while allocating a new ID from the IDR,
you may need to pass a restrictive set of GFP flags, which can lead
to the IDR being unable to allocate memory.  To work around this,
you can call idr_preload() before taking the lock, and then
idr_preload_end() after the allocation.

.. kernel-doc:: include/linux/idr.h
   :doc: idr sync

IDA usage
=========

.. kernel-doc:: lib/idr.c
   :doc: IDA description

Functions and structures
========================

.. kernel-doc:: include/linux/idr.h
   :functions:
.. kernel-doc:: lib/idr.c
   :functions:
