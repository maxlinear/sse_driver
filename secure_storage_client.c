/*******************************************************************************

  Copyright (C) 2021-2022  MaxLinear, Inc.

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

*******************************************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/random.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/ioctl.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <linux/stat.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <asm/io.h>
#include "drv_icc.h"
#include "drv_mps.h"
#include "secure_storage_client.h"
#include <linux/genalloc.h>
#include <soc/mxl/mxl_sec.h>
#include <soc/mxl/mxl_gen_pool.h>
#include <linux/dma-direct.h>
#include <linux/platform_device.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MaxLinear Inc");
MODULE_DESCRIPTION("Secure Storage Driver");

struct mutex sec_storage_client_mutex;
static wait_queue_head_t sec_storage_wakeuplist;
static refcount_t sec_storage_wakeup = REFCOUNT_INIT(0);

typedef struct sst_iccpool_info {
	struct device *icc_dev;
	struct gen_pool *icc_pool;
} iccpool_info_t;

static iccpool_info_t iccpool_inf;

#ifdef SST_DEBUG
static void dump_ss_config(sst_config_t *dump_msg)
{
	if (!dump_msg)
		return;

	pr_debug("UID %d\n", dump_msg->uid_val);
	pr_debug("GID %d\n", dump_msg->gid_val);
	pr_debug("pname %s\n", dump_msg->pname);
	pr_debug("src data buff %x\n", dump_msg->pdata_buf);
	pr_debug("object_src_data_len %d\n", dump_msg->data_len);
	pr_debug("object name %s\n", dump_msg->obj_name);
	pr_debug("SST object policy attr %x\n", dump_msg->policy.policy_attr.u.attr);
	pr_debug("SST object policy perms %x\n", dump_msg->policy.access_perm.u.perms);
	pr_debug("sizeof sst_config_t %ld\n", sizeof(sst_config_t));

	return;
}
#endif

long sse_sec_storage_client_ioctl(struct file *fd,
						unsigned int cmd, unsigned long arg)
{
    sst_param_t *sst_param = NULL;
    sst_data_param_t *sst_data_param = NULL;
    sst_config_t *secure_store_config = NULL;
    const struct cred *cred = NULL;
	int dev = 0;
    int ret = 0;
    bool isadmin = false;

	secure_store_config = (void *)gen_pool_alloc(iccpool_inf.icc_pool, sizeof(sst_config_t));
	if (secure_store_config == NULL) {
		pr_err("Memory Allocation for secure storage struct failed. \r\n");
		ret = -ENOMEM;
		goto finish;
	}
    memset(secure_store_config, 0, sizeof(sst_config_t));
	mutex_lock(&sec_storage_client_mutex);
	dev = MINOR(fd->f_inode->i_rdev);

    if (dev == ICC_SEC_STG_ADMIN_NR) {
        /* DAC Enforcement Check */
        if(!capable(CAP_SYS_ADMIN)) {
            ret = -EACCES;
            pr_err("DAC Enformcement check failed\n");
            goto finish;
        }
    }
    /* Get uid & GID & process name */
    cred = current_cred();
    secure_store_config->uid_val = cred->uid.val;
    secure_store_config->gid_val = cred->gid.val;
    strncpy(secure_store_config->pname, current->comm, TASK_COMM_LEN);
#ifdef SST_DEBUG
    pr_info("secure storage client : process name [%s] uid [%d] gid [%d]\n",
            secure_store_config->pname, secure_store_config->uid_val,
            secure_store_config->uid_val);
    pr_info
        ("secure storage client : devnode uid [%d]  - devnode gid [%d]\n",
         fd->f_inode->i_uid.val, fd->f_inode->i_gid.val);
#endif
	/* ssregular node have all the permission(0666) and so no need to
	 * check for permission in case of ssregular node call.
	 * Also ssregular node can be opened by different user as well,
	 * so can't compare the per user UID and GID (dynamic) against
	 * ssregular node which have fixed owner and group (root) and UID
	 * and GID (0)as well.
	 */
	if (dev == ICC_SEC_STG_ADMIN_NR) {
		isadmin = true;
		if ((S_IRUSR & fd->f_inode->i_mode) || (S_IWUSR & fd->f_inode->i_mode)) {
			if (fd->f_inode->i_uid.val != secure_store_config->uid_val) {
				ret = -EPERM;
				goto finish;
			}
		}

		if ((S_IRGRP & fd->f_inode->i_mode) || (S_IWGRP & fd->f_inode->i_mode)) {
			if (fd->f_inode->i_gid.val != secure_store_config->gid_val) {
				ret = -EPERM;
				goto finish;
			}
		}
		if ((S_IROTH & fd->f_inode->i_mode) || (S_IWOTH & fd->f_inode->i_mode)) {
			ret = -EPERM;
			goto finish;
		}
	}

	secure_store_config->policy.policy_attr.u.field.admin_store = isadmin;

    switch (cmd) {
        case SS_STG_CREATE_OPEN:
			pr_debug("SS_STG_CREATE_OPEN ioctl get invoked\n");
            if ((sst_param = kzalloc(sizeof(sst_param_t), GFP_DMA)) == NULL) {
				pr_err("Allocation failed. \r\n");
                ret = -ENOMEM;
                goto finish;
            }
            /* Copy the user data into kernel memory */
            if (copy_from_user(sst_param, (void *)arg, sizeof(sst_param_t))) {
                pr_err("copy_from_user error\r\n");
                ret = -EFAULT;
                goto finish;
            }

			/* Construct icc_msg_t */
			ret = sse_secure_storage_create_open(sst_param, secure_store_config);
            if (ret < 0) {
                pr_err("secure storage Failed to open the Object\n");
                goto finish;
            }
            if (copy_to_user((void *)arg, sst_param, sizeof(sst_param_t))) {
                pr_err("copy_to_user error\r\n");
                ret = -EFAULT;
                goto finish;
            }
            break;
        case SS_STG_SAVE:
			pr_debug("SS_STG_SAVE ioctl get invoked\n");
            if ((sst_data_param =
                kzalloc(sizeof(sst_data_param_t), GFP_DMA)) == NULL) {
				pr_err("Allocation failed. \r\n");
                ret = -ENOMEM;
                goto finish;
            }
            if (copy_from_user
               (sst_data_param, (void *)arg, sizeof(sst_data_param_t))) {
                pr_err(" secure storage save copy_from_user error\r\n");
                ret = -EFAULT;
                goto finish;
            }
			ret =
				sse_secure_storage_save(sst_data_param, secure_store_config);
            if (ret < 0) {
                pr_err("secure storage Failed to save the Object\n");
                goto finish;
            }
            break;
        case SS_STG_RESTORE:
			pr_debug("SS_STG_LOAD ioctl get invoked\n");
			if ((sst_data_param =
				kzalloc(sizeof(sst_data_param_t), GFP_DMA)) == NULL) {
				pr_err("Allocation failed. \r\n");
				ret = -ENOMEM;
				goto finish;
			}
            if (copy_from_user
               (sst_data_param, (void *)arg, sizeof(sst_data_param_t))) {
                pr_err(" secure storage retrieve copy_from_user error\r\n");
                ret = -EFAULT;
                goto finish;
            }
			ret =
				sse_secure_storage_load(sst_data_param, secure_store_config);
            if (ret < 0) {
                pr_err("secure storage Failed to load the Object\n");
                goto finish;
            }
            break;
        case SS_STG_DELETE_CLOSE:
			pr_debug("SS_STG_DELETE_CLOSE ioctl get invoked\n");
            if ((sst_param =
                kzalloc(sizeof(sst_param_t), GFP_DMA)) == NULL) {
				pr_err("Allocation failed.\r\n");
                ret = -ENOMEM;
                goto finish;
            }

            if (copy_from_user
               (sst_param, (void *)arg, sizeof(sst_param_t))) {
                pr_err(" secure storage delete copy_from_user error\r\n");
                ret = -EFAULT;
                goto finish;
            }
			ret =
				sse_secure_storage_close_delete(sst_param, secure_store_config);
            if (ret < 0) {
                pr_err("secure storage Failed to delete the Object\n");
                goto finish;
            }
            break;
        default:
            ret = -EINVAL;
            pr_err("Invalid ioctl cmd\r\n");
            break;
    }
 finish:
    mutex_unlock(&sec_storage_client_mutex);
	if (sst_param)
		kfree(sst_param);
	if (sst_data_param)
		kfree(sst_data_param);
	if (secure_store_config)
		gen_pool_free(iccpool_inf.icc_pool, (unsigned long)secure_store_config, sizeof(sst_config_t));

	return ret;
}

int sse_secure_storage_create_open(sst_param_t *sst_param,
								sst_config_t *secure_store_config)
{
    icc_msg_t *ret_msg = NULL, sst_client_msg;
    int ret = 0;
    memset(&sst_client_msg, 0, sizeof(icc_msg_t));

    /* Copy the user data to secure_store_config and send to TEP */
    strncpy(secure_store_config->obj_name, sst_param->objectname,
            FILEPNAME_MAX);
    memcpy(&secure_store_config->policy.access_perm,
           &sst_param->sst_access_policy.access_perm, sizeof(sst_access_perm_t));
    memcpy(&secure_store_config->policy.policy_attr,
           &sst_param->sst_access_policy.policy_attr, sizeof(sst_policy_attr_t));
    strncpy(secure_store_config->policy.pname, current->comm, TASK_COMM_LEN);
	secure_store_config->policy.uid_val = secure_store_config->uid_val;
	secure_store_config->policy.gid_val = secure_store_config->gid_val;
    secure_store_config->flags = sst_param->secure_store_flags;
    sst_client_msg.msg_id = SS_SST_CREATE_OPEN;

    if ((ret_msg = kzalloc(sizeof(icc_msg_t), GFP_DMA)) == NULL) {
        pr_err("Allocation failed. \r\n");
        ret = -EFAULT;
        goto finish;
    }

	ret = sse_secure_storage_send_icc_msg(&sst_client_msg, ret_msg, secure_store_config);
	if (!ret) {
		sst_param->ss_handle = (((long int)ret_msg->param[SS_ICC_PARAM_2] & 0xffffffff) << 32);
		sst_param->ss_handle = (long int)ret_msg->param[SS_ICC_PARAM_1] | sst_param->ss_handle;
		ret = (char)ret_msg->param_attr;
#ifdef SST_DEBUG
		pr_info(KERN_INFO
			"ss handle[%lx]\n",sst_param->ss_handle);
#endif
	}

finish:
	if (ret_msg)
		kfree(ret_msg);

	return ret;
}

int sse_secure_storage_save(sst_data_param_t *sst_save_param,
							sst_config_t *secure_store_config)
{
    icc_msg_t *ret_msg = NULL, sst_client_msg;
    int ret = 0;
    void *data_buf = NULL;
	dma_addr_t sst_dma_addr;

    memset(&sst_client_msg, 0, sizeof(icc_msg_t));

	if (sst_save_param->payload_len <= 0) {
		pr_err("Requested data length is not valid\n");
		ret = -EAGAIN;
		goto finish;
	}

	data_buf = (void *)gen_pool_alloc(iccpool_inf.icc_pool, sst_save_param->payload_len);
	if (data_buf == NULL) {
		pr_err("Memory Allocation for SST_Save failed\n");
		ret = -ENOMEM;
		goto finish;
	}

    if (copy_from_user
       (data_buf, sst_save_param->payload, sst_save_param->payload_len)) {
        pr_err("copy_from_user error\r\n");
        ret = -EAGAIN;
        goto finish;
    }
    sst_client_msg.msg_id = SS_SST_SAVE;
	sst_dma_addr = dma_map_single_attrs(iccpool_inf.icc_dev, data_buf,
				sst_save_param->payload_len, DMA_BIDIRECTIONAL, DMA_ATTR_NON_CONSISTENT);

	if (dma_mapping_error(iccpool_inf.icc_dev, sst_dma_addr)) {
		pr_err("<Secure Storage Client> Unable to map sst data buffer\n");
		ret = -ENOMEM;
		goto finish;
	}

	dma_sync_single_for_device(iccpool_inf.icc_dev, sst_dma_addr, sst_save_param->payload_len, DMA_TO_DEVICE);
	secure_store_config->pdata_buf = (uint32_t)sst_dma_addr;
    secure_store_config->data_len = sst_save_param->payload_len;
    sst_client_msg.param[SS_ICC_PARAM_1] =
        (uint32_t) (sst_save_param->ss_handle & 0xffffffff);
    sst_client_msg.param[SS_ICC_PARAM_2] =
        (uint32_t) ((sst_save_param->ss_handle >> 32) & 0xffffffff);
#ifndef SYNC_ICC_COMM
    if((ret_msg = kzalloc(sizeof(icc_msg_t), GFP_DMA)) == NULL) {
		pr_err("Allocation failed\n");
        ret = -ENOMEM;
        goto finish;
    }
#endif
	ret = sse_secure_storage_send_icc_msg(&sst_client_msg, ret_msg, secure_store_config);
	if (!ret)
		ret = (char)ret_msg->param_attr;

finish:
	if (ret_msg)
		kfree(ret_msg);

	if (data_buf) {
		dma_sync_single_for_cpu(iccpool_inf.icc_dev, sst_dma_addr, sst_save_param->payload_len, DMA_TO_DEVICE);
		gen_pool_free(iccpool_inf.icc_pool, (unsigned long)data_buf, sst_save_param->payload_len);
	}

	return ret;
}

int sse_secure_storage_load(sst_data_param_t *sst_load_param,
					sst_config_t *secure_store_config)
{
    icc_msg_t *ret_msg = NULL, sst_client_msg;
    int ret = 0;
    void *data_buf = NULL;
	dma_addr_t sst_dma_addr;

    memset(&sst_client_msg, 0, sizeof(icc_msg_t));

    if (!sst_load_param->payload || sst_load_param->payload_len <= 0) {
        pr_err
            ("Requested data length (or) Requested data buffer is not valid\n");
        ret = -EAGAIN;
        goto finish;
    }

	data_buf = (void *)gen_pool_alloc(iccpool_inf.icc_pool, sst_load_param->payload_len);
	if (data_buf == NULL) {
		pr_err("Memory Allocation for SST_Load failed\n");
		ret = -ENOMEM;
		goto finish;
	}

	sst_client_msg.msg_id = SS_SST_RETRIEVE;
	sst_dma_addr = dma_map_single_attrs(iccpool_inf.icc_dev, data_buf,
				sst_load_param->payload_len, DMA_BIDIRECTIONAL, DMA_ATTR_NON_CONSISTENT);

	if (dma_mapping_error(iccpool_inf.icc_dev, sst_dma_addr)) {
		pr_err("<Secure Storage Client> Unable to map sst data buffer\n");
		ret = -ENOMEM;
		goto finish;
	}

	secure_store_config->pdata_buf = (uint32_t)sst_dma_addr;
	secure_store_config->data_len = sst_load_param->payload_len;
    sst_client_msg.param[SS_ICC_PARAM_1] =
        (uint32_t) (sst_load_param->ss_handle & 0xffffffff);
    sst_client_msg.param[SS_ICC_PARAM_2] =
        (uint32_t) ((sst_load_param->ss_handle >> 32) & 0xffffffff);
#ifndef SYNC_ICC_COMM
    if((ret_msg = kzalloc(sizeof(icc_msg_t), GFP_DMA)) == NULL) {
		pr_err("Allocation failed\n");
        ret = -ENOMEM;
        goto finish;
    }
#endif
	ret = sse_secure_storage_send_icc_msg(&sst_client_msg, ret_msg, secure_store_config);
	if (!ret) {
		ret = (ret_msg->param_attr == 0) ? ret_msg->param[SS_ICC_PARAM_0] : (char)ret_msg->param_attr;
		if (ret < 0)
			goto finish;
		dma_sync_single_for_cpu(iccpool_inf.icc_dev, sst_dma_addr, ret, DMA_FROM_DEVICE);
		if (copy_to_user((void *)sst_load_param->payload, data_buf, ret)) {
			pr_err("copy_to_user error\r\n");
			ret = -EFAULT;
			goto finish;
		}
	}

finish:
	if (ret_msg)
		kfree(ret_msg);

	if (data_buf)
		gen_pool_free(iccpool_inf.icc_pool, (unsigned long)data_buf, sst_load_param->payload_len);

	return ret;
}

int sse_secure_storage_close_delete(sst_param_t *sst_del_param,
								sst_config_t *secure_store_config)
{
    icc_msg_t *ret_msg = NULL, sst_client_msg;
    int ret = 0;
    void *data_buf = NULL;

    memset(&sst_client_msg, 0, sizeof(icc_msg_t));
    sst_client_msg.msg_id = SS_SST_DELETE_CLOSE;
	secure_store_config->flags = sst_del_param->secure_store_flags;
    sst_client_msg.param[SS_ICC_PARAM_1] =
        (uint32_t) (sst_del_param->ss_handle & 0xffffffff);
    sst_client_msg.param[SS_ICC_PARAM_2] =
        (uint32_t) ((sst_del_param->ss_handle >> 32) & 0xffffffff);
#ifndef SYNC_ICC_COMM
    if ((ret_msg = kzalloc(sizeof(icc_msg_t), GFP_DMA)) == NULL) {
		pr_err("Allocation failed\n");
		ret = -ENOMEM;
		goto finish;
	}
#endif
	ret = sse_secure_storage_send_icc_msg(&sst_client_msg, ret_msg, secure_store_config);
	if (!ret)
		ret = (char)ret_msg->param_attr;

finish:
	if (ret_msg)
		kfree(ret_msg);
	if (data_buf)
		kfree(data_buf);

	return ret;
}

int sse_secure_storage_send_icc_msg(icc_msg_t *sst_client_msg,
                                    icc_msg_t *sst_reply_msg,
                                    sst_config_t *secure_store_config)
{
	dma_addr_t sst_cfg_dma_addr, pObjectId;
	void *sst_ObjectID = NULL;
	int timeout;
	int ret = 0;
#ifdef SST_DEBUG
	pr_info("<Secure Storage Client> Sending ICC msg\n");
#endif
    sst_client_msg->src_client_id = SECURE_STORAGE;
    sst_client_msg->dst_client_id = SECURE_STORAGE;
    sst_client_msg->param_attr = ICC_PARAM_PTR | (ICC_PARAM_PTR_NON_IOCU << 1);
	sst_client_msg->icc_flags.priority =
					secure_store_config->policy.policy_attr.u.field.admin_store;

	sst_ObjectID = (void *)gen_pool_alloc(iccpool_inf.icc_pool, OBJ_ID_SIZE);
	if (sst_ObjectID == NULL) {
		pr_err("Memory Allocation For Object ID failed. \r\n");
		ret = -ENOMEM;
		goto out;
	}

	pObjectId = dma_map_single_attrs(iccpool_inf.icc_dev, (void *)sst_ObjectID,
				OBJ_ID_SIZE, DMA_BIDIRECTIONAL, DMA_ATTR_NON_CONSISTENT);

	if (dma_mapping_error(iccpool_inf.icc_dev, pObjectId)) {
		pr_err("<Secure Storage Client> Unable to map SST object buffer\n");
		ret = -ENOMEM;
		goto out;
	}


	sst_cfg_dma_addr = dma_map_single_attrs(iccpool_inf.icc_dev, (void *)secure_store_config,
				sizeof(sst_config_t), DMA_BIDIRECTIONAL, DMA_ATTR_NON_CONSISTENT);

	if (dma_mapping_error(iccpool_inf.icc_dev, sst_cfg_dma_addr)) {
		pr_err("<Secure Storage Client> Unable to map secure store config\n");
		return -ENOMEM;
	}

	dma_sync_single_for_device(iccpool_inf.icc_dev, sst_cfg_dma_addr, sizeof(sst_config_t), DMA_TO_DEVICE);
	sst_client_msg->param[SS_ICC_PARAM_0] = (uint32_t)sst_cfg_dma_addr;
	sst_client_msg->param[SS_ICC_PARAM_3] = (uint32_t)pObjectId;

#ifdef SST_DEBUG
	dump_ss_config(secure_store_config);
	dump_ss_icc_msg(sst_client_msg);
#endif

#ifdef SYNC_ICC_COMM
    sst_reply_msg = icc_sync_write(SECURE_STORAGE, sst_client_msg);
    if(!sst_reply_msg || sst_reply_msg->dst_client_id != SECURE_STORAGE
       || sst_client_msg->msg_id != SS_SST_SAVE_RES) {
        if(sst_reply_msg)
            pr_info(KERN_INFO
                    "received client id %d : reiceived msg id %x \r\n",
                    sst_reply_msg->dst_client_id, sst_reply_msg->msg_id);
        return -ENOMSG;
    }
#else
	if (icc_write(SECURE_STORAGE, sst_client_msg) <= 0) {
		pr_err("Failed to write icc msg \r\n");
		ret = -ECONNREFUSED;
		goto out;
	}

	timeout = wait_event_interruptible_timeout(sec_storage_wakeuplist,
				(refcount_read(&sec_storage_wakeup) != 0), msecs_to_jiffies(SSS_ICC_REQ_TIMEOUT * HZ));
	if (timeout == 0) {
		pr_err("<Secure Store Client> SST request timeout");
		ret = -ETIMEDOUT;
		goto out;
	}

	if (icc_read(SECURE_STORAGE, sst_reply_msg) < 0) {
		pr_err("Failed to read icc msg \r\n");
		ret = -ETIMEDOUT;
		goto out;
	}
#endif
#ifdef SST_DEBUG
	dump_ss_icc_msg(sst_reply_msg);
#endif
out:
	if (sst_ObjectID)
		gen_pool_free(iccpool_inf.icc_pool, (unsigned long)sst_ObjectID, OBJ_ID_SIZE);
	refcount_set(&sec_storage_wakeup, 0);
	dma_sync_single_for_cpu(iccpool_inf.icc_dev, sst_cfg_dma_addr, sizeof(sst_config_t), DMA_TO_DEVICE);
	return ret;
}

void pfn_sse_sec_storage_callback(icc_wake_type wake_type)
{
	if	((wake_type & ICC_READ)) {
		refcount_set(&sec_storage_wakeup, 1);
		wake_up_interruptible(&sec_storage_wakeuplist);
	}
}

int __init sse_sec_storage_client_init(void)
{
    int ret = 0;
    ret = icc_open((struct inode *)SECURE_STORAGE, NULL);
    if(ret < 0) {
        pr_err("open ICC Failed for secure storage client\n");
		ret = -ENODEV;
        goto out;
    }

    ret = icc_register_callback(SECURE_STORAGE, &pfn_sse_sec_storage_callback);
    if(ret < 0) {
        pr_err("CallBack Register with ICC Failed for secure storage\n");
		ret = -EACCES;
        goto close_icc_dev;
    }

	iccpool_inf.icc_dev = icc_get_genpool_dev();
	if (iccpool_inf.icc_dev == NULL) {
		pr_err("Failed to get the genpool dev\n");
		ret = -EFAULT;
		goto finish;
	}

	iccpool_inf.icc_pool = icc_get_genpool();
	if (iccpool_inf.icc_pool == NULL) {
		pr_err("Failed to get the ICC genpool\n");
		ret = -EFAULT;
		goto finish;
	}

	init_waitqueue_head(&sec_storage_wakeuplist);
	mutex_init(&sec_storage_client_mutex);
	return ret;

finish:
	icc_unregister_callback(SECURE_STORAGE);
close_icc_dev:
	icc_close((struct inode *)SECURE_STORAGE, NULL);
out:
	return ret;
}

void __exit sse_sec_storage_client_cleanup(void)
{
    icc_unregister_callback(SECURE_STORAGE);
    icc_close((struct inode *)SECURE_STORAGE, NULL);
}
