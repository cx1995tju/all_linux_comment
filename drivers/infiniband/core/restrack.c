// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2017-2018 Mellanox Technologies. All rights reserved.
 */

#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/restrack.h> // resource track
#include <rdma/rdma_counter.h>
#include <linux/mutex.h>
#include <linux/sched/task.h>
#include <linux/pid_namespace.h>

#include "cma_priv.h"
#include "restrack.h"

/* XXX: 资源跟踪功能
 * - 从各个函数的参数看, 资源的粒度是 device
 *
 * - 重要函数
 *
 *  1. **资源跟踪初始化与清理**  
 *     - `rdma_restrack_init`：初始化资源跟踪结构，为每种资源类型分配跟踪根节点。
 *     - `rdma_restrack_clean`：清理资源跟踪结构，检测并报告未释放的资源泄漏。
 *
 *  2. **资源添加、删除与引用计数**  
 *     - `rdma_restrack_add`：将新创建的资源对象添加到跟踪数据库。
 *     - `rdma_restrack_del`：从数据库中删除资源对象，并处理引用计数和同步。
 *     - `rdma_restrack_get`/`rdma_restrack_put`：实现资源对象的引用计数，确保资源安全释放。
 *
 *  3. **资源属性设置与查询**  
 *     - `rdma_restrack_set_name`/`rdma_restrack_parent_name`：设置资源的拥有者信息（如任务或内核模块名）。
 *     - `rdma_restrack_count`：查询某类资源的当前使用数量。
 *     - `rdma_restrack_get_byid`：通过资源 ID 查找并获取资源对象。
 *
 *  4. **辅助工具函数**  
 *     - `type2str`：将资源类型转换为字符串。
 *     - `res_to_dev`：根据资源对象获取所属设备。
 *
 *
 * - 重要数据结构
 *   - ~rdma_restrack_root~   per-device 的组织所有资源的 root
 *   - ~rdma_restrack_entry~  每个资源一个 entry
 *
 *
 *
 * - 接口
 *
 *
 * - Q&A:
 *   - resource 是什么?
 *   - 为什么要 track ?
 *     - 因为 bypass 内核了, 所以用户态用的有些资源需要额外 track ???
 *
 * */

/**
 * rdma_restrack_init() - initialize and allocate resource tracking
 * @dev:  IB device
 *
 * Return: 0 on success
 *
 *
 * 创建 ib 设备的时候调用
 */
int rdma_restrack_init(struct ib_device *dev)
{
	struct rdma_restrack_root *rt;
	int i;

	// 每种资源一个 entry
	dev->res = kcalloc(RDMA_RESTRACK_MAX, sizeof(*rt), GFP_KERNEL);
	if (!dev->res)
		return -ENOMEM;

	rt = dev->res;

	// 然后每类资源初始化一个数组 xarray
	for (i = 0; i < RDMA_RESTRACK_MAX; i++)
		xa_init_flags(&rt[i].xa, XA_FLAGS_ALLOC);

	return 0;
}

static const char *type2str(enum rdma_restrack_type type)
{
	static const char * const names[RDMA_RESTRACK_MAX] = {
		[RDMA_RESTRACK_PD] = "PD",
		[RDMA_RESTRACK_CQ] = "CQ",
		[RDMA_RESTRACK_QP] = "QP",
		[RDMA_RESTRACK_CM_ID] = "CM_ID",
		[RDMA_RESTRACK_MR] = "MR",
		[RDMA_RESTRACK_CTX] = "CTX",
		[RDMA_RESTRACK_COUNTER] = "COUNTER",
	};

	return names[type];
};

/**
 * rdma_restrack_clean() - clean resource tracking
 * @dev:  IB device
 */
void rdma_restrack_clean(struct ib_device *dev)
{
	struct rdma_restrack_root *rt = dev->res;
	struct rdma_restrack_entry *e;
	char buf[TASK_COMM_LEN];
	bool found = false;
	const char *owner;
	int i;

	// 计算资源还是被持有的, 也还是会去释放的, 只不过是打印一些 log 而已
	for (i = 0 ; i < RDMA_RESTRACK_MAX; i++) {
		struct xarray *xa = &dev->res[i].xa;

		if (!xa_empty(xa)) {
			unsigned long index;

			if (!found) {
				pr_err("restrack: %s", CUT_HERE);
				dev_err(&dev->dev, "BUG: RESTRACK detected leak of resources\n");
			}
			xa_for_each(xa, index, e) {
				if (rdma_is_kernel_res(e)) {
					owner = e->kern_name;
				} else {
					/*
					 * There is no need to call get_task_struct here,
					 * because we can be here only if there are more
					 * get_task_struct() call than put_task_struct().
					 */
					get_task_comm(buf, e->task);
					owner = buf;
				}

				pr_err("restrack: %s %s object allocated by %s is not freed\n",
				       rdma_is_kernel_res(e) ? "Kernel" :
							       "User",
				       type2str(e->type), owner);
			}
			found = true;
		}
		xa_destroy(xa);
	}
	if (found)
		pr_err("restrack: %s", CUT_HERE);

	kfree(rt);
}

/**
 * rdma_restrack_count() - the current usage of specific object
 * @dev:  IB device
 * @type: actual type of object to operate
 */
int rdma_restrack_count(struct ib_device *dev, enum rdma_restrack_type type)
{
	struct rdma_restrack_root *rt = &dev->res[type];
	struct rdma_restrack_entry *e;
	XA_STATE(xas, &rt->xa, 0);
	u32 cnt = 0;

	xa_lock(&rt->xa);
	xas_for_each(&xas, e, U32_MAX) // 检查这类资源里的 entry 数量
		cnt++;
	xa_unlock(&rt->xa);
	return cnt;
}
EXPORT_SYMBOL(rdma_restrack_count);

static struct ib_device *res_to_dev(struct rdma_restrack_entry *res)
{
	switch (res->type) {
	case RDMA_RESTRACK_PD:
		return container_of(res, struct ib_pd, res)->device;
	case RDMA_RESTRACK_CQ:
		return container_of(res, struct ib_cq, res)->device;
	case RDMA_RESTRACK_QP:
		return container_of(res, struct ib_qp, res)->device;
	case RDMA_RESTRACK_CM_ID:
		return container_of(res, struct rdma_id_private,
				    res)->id.device;
	case RDMA_RESTRACK_MR:
		return container_of(res, struct ib_mr, res)->device;
	case RDMA_RESTRACK_CTX:
		return container_of(res, struct ib_ucontext, res)->device;
	case RDMA_RESTRACK_COUNTER:
		return container_of(res, struct rdma_counter, res)->device;
	default:
		WARN_ONCE(true, "Wrong resource tracking type %u\n", res->type);
		return NULL;
	}
}

/**
 * rdma_restrack_attach_task() - attach the task onto this resource,
 * valid for user space restrack entries.
 * @res:  resource entry
 * @task: the task to attach
 *
 * 资源分配给用户态的 task
 */
static void rdma_restrack_attach_task(struct rdma_restrack_entry *res,
				      struct task_struct *task)
{
	if (WARN_ON_ONCE(!task))
		return;

	if (res->task)
		put_task_struct(res->task);
	get_task_struct(task);
	res->task = task;
	res->user = true;
}

/**
 * rdma_restrack_set_name() - set the task for this resource
 * @res:  resource entry
 * @caller: kernel name, the current task will be used if the caller is NULL.
 */
void rdma_restrack_set_name(struct rdma_restrack_entry *res, const char *caller)
{
	if (caller) {
		res->kern_name = caller;
		return;
	}

	rdma_restrack_attach_task(res, current);
}
EXPORT_SYMBOL(rdma_restrack_set_name);

/**
 * rdma_restrack_parent_name() - set the restrack name properties based
 * on parent restrack
 * @dst: destination resource entry
 * @parent: parent resource entry
 *
 * 用 parent resource 的属性来设置 dst resource 的属性
 */
void rdma_restrack_parent_name(struct rdma_restrack_entry *dst,
			       const struct rdma_restrack_entry *parent)
{
	if (rdma_is_kernel_res(parent))
		dst->kern_name = parent->kern_name;
	else
		rdma_restrack_attach_task(dst, parent->task);
}
EXPORT_SYMBOL(rdma_restrack_parent_name);

/**
 * rdma_restrack_new() - Initializes new restrack entry to allow _put() interface
 * to release memory in fully automatic way.
 * @res - Entry to initialize
 * @type - REstrack type
 *
 * 创建资源
 */
void rdma_restrack_new(struct rdma_restrack_entry *res,
		       enum rdma_restrack_type type)
{
	kref_init(&res->kref);
	init_completion(&res->comp);
	res->type = type;
}
EXPORT_SYMBOL(rdma_restrack_new);

/**
 * rdma_restrack_add() - add object to the reource tracking database
 * @res:  resource entry
 *
 * resource 加入到 ib_device 里去管理
 *
 * 不同资源的 id 还是不同的:
 * - QP 用 QPN
 * - COUNTER 用 couter id
 * - 其他资源用分配的 resource id
 */
void rdma_restrack_add(struct rdma_restrack_entry *res)
{
	struct ib_device *dev = res_to_dev(res);
	struct rdma_restrack_root *rt;
	int ret;

	if (!dev)
		return;

	rt = &dev->res[res->type];

	if (res->type == RDMA_RESTRACK_QP) {
		/* Special case to ensure that LQPN points to right QP */
		struct ib_qp *qp = container_of(res, struct ib_qp, res);

		ret = xa_insert(&rt->xa, qp->qp_num, res, GFP_KERNEL);
		res->id = ret ? 0 : qp->qp_num;
	} else if (res->type == RDMA_RESTRACK_COUNTER) {
		/* Special case to ensure that cntn points to right counter */
		struct rdma_counter *counter;

		counter = container_of(res, struct rdma_counter, res);
		ret = xa_insert(&rt->xa, counter->id, res, GFP_KERNEL);
		res->id = ret ? 0 : counter->id;
	} else {
		ret = xa_alloc_cyclic(&rt->xa, &res->id, res, xa_limit_32b,
				      &rt->next_id, GFP_KERNEL);
	}

	if (!ret)
		res->valid = true;
}
EXPORT_SYMBOL(rdma_restrack_add);

int __must_check rdma_restrack_get(struct rdma_restrack_entry *res)
{
	// 增加引用计数 (在当前引用计数不为 0 的情况下)
	return kref_get_unless_zero(&res->kref);
}
EXPORT_SYMBOL(rdma_restrack_get);

/**
 * rdma_restrack_get_byid() - translate from ID to restrack object
 * @dev: IB device
 * @type: resource track type
 * @id: ID to take a look
 *
 * Return: Pointer to restrack entry or -ENOENT in case of error.
 *
 * 获取资源结构
 */
struct rdma_restrack_entry *
rdma_restrack_get_byid(struct ib_device *dev,
		       enum rdma_restrack_type type, u32 id)
{
	struct rdma_restrack_root *rt = &dev->res[type];
	struct rdma_restrack_entry *res;

	xa_lock(&rt->xa);
	res = xa_load(&rt->xa, id);
	if (!res || !rdma_restrack_get(res))
		res = ERR_PTR(-ENOENT);
	xa_unlock(&rt->xa);

	return res;
}
EXPORT_SYMBOL(rdma_restrack_get_byid);

static void restrack_release(struct kref *kref)
{
	struct rdma_restrack_entry *res;

	res = container_of(kref, struct rdma_restrack_entry, kref);
	if (res->task) {
		put_task_struct(res->task);
		res->task = NULL;
	}
	complete(&res->comp);
}

int rdma_restrack_put(struct rdma_restrack_entry *res)
{
	// 释放引用计数
	return kref_put(&res->kref, restrack_release);
}
EXPORT_SYMBOL(rdma_restrack_put);

/**
 * rdma_restrack_del() - delete object from the reource tracking database
 * @res:  resource entry
 *
 * 资源删除后要等待 release 调用
 */
void rdma_restrack_del(struct rdma_restrack_entry *res)
{
	struct rdma_restrack_entry *old;
	struct rdma_restrack_root *rt;
	struct ib_device *dev;

	if (!res->valid) {
		if (res->task) {
			put_task_struct(res->task);
			res->task = NULL;
		}
		return;
	}

	dev = res_to_dev(res);
	if (WARN_ON(!dev))
		return;

	rt = &dev->res[res->type];

	old = xa_erase(&rt->xa, res->id);
	if (res->type == RDMA_RESTRACK_MR || res->type == RDMA_RESTRACK_QP)
		return;
	WARN_ON(old != res);
	res->valid = false;

	rdma_restrack_put(res);
	wait_for_completion(&res->comp); // 阻塞的
}
EXPORT_SYMBOL(rdma_restrack_del);
