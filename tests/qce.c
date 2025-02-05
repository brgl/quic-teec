#include <sys/mman.h>
#include "tests_private.h"
#include <sys/random.h>
#include "qcedev.h"
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>
#include <linux/dma-heap.h>
#include <linux/dma-buf.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define IQceTest_ALGO_MODE_AES_CBC		1
#define IQceTest_OPERATION_ENCRYPT_ALLOWED	1
#define IQceTest_PIPE_OFFLOAD_HLOS_HLOS		1

struct key_params {
	uint8_t key[32];
	uint64_t key_len;
	uint64_t timer;
	uint32_t pause_sensitive;
	uint32_t algo_mode;
	uint32_t ops_allowed; 
	uint32_t pipe;
};

static int set_key(struct qcomtee_object *ta)
{
	struct key_params key_params;
	struct qcomtee_param params;
	qcomtee_result_t result;
	ssize_t ret;

	memset(&key_params, 0, sizeof(key_params));

	ret = getrandom(key_params.key, sizeof(key_params.key), 0);
	if (ret < 0) {
		PRINT("random fail %ld\n", ret);
		return -1;
	}

	key_params.key_len = 16;
	key_params.algo_mode = IQceTest_ALGO_MODE_AES_CBC;
	key_params.ops_allowed = IQceTest_OPERATION_ENCRYPT_ALLOWED;
	key_params.pipe = IQceTest_PIPE_OFFLOAD_HLOS_HLOS;
	key_params.pause_sensitive = 0;
	key_params.timer = 0;

 	params.attr = QCOMTEE_UBUF_INPUT;
 	params.ubuf = UBUF_INIT(&key_params);

 	if (qcomtee_object_invoke(ta, 0, &params, 1, &result) ||
	    (result != QCOMTEE_OK)) {
		PRINT("Not OK %u\n", result);
		return -1;
	}

	return 0;
}

static void *alloc_dma_buf(int qce_fd)
{
	struct qcedev_map_buf_req map;
	struct dma_heap_allocation_data alloc_data;
	void *ptr;
	int fd, ret;

	memset(&alloc_data, 0, sizeof(alloc_data));

	fd = open("/dev/dma_heap/system", O_RDWR);
	if (fd < 0) {
		perror("Failed to open DMA heap");
		return NULL;
	}

        alloc_data.len = 4096,
        alloc_data.fd_flags = O_RDWR,
        alloc_data.heap_flags = 0,

	ret = ioctl(fd, DMA_HEAP_IOCTL_ALLOC, &alloc_data);
	if (ret < 0) {
		perror("DMA heap allocation failed");
		close(fd);
		return NULL;
	}

	ptr = mmap(NULL, 16, PROT_READ | PROT_WRITE, MAP_SHARED,
		   alloc_data.fd, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}

	memset(&map, 0, sizeof(map));
	map.fd[0] = alloc_data.fd;
	map.fd_offset[0] = 0;
	map.fd_size[0] = 16;
	map.num_fds = 1;

	ret = ioctl(qce_fd, QCEDEV_IOCTL_MAP_BUF_REQ, &map);
	if (ret < 0) {
		perror("ioctl map");
		return NULL;
	}

	return (void *)map.buf_vaddr[0];
}

static int encrypt_data(struct qcomtee_object *ta)
{
	void *in, *out;
	struct qcedev_offload_cipher_op_req req;
	ssize_t ret;
	int fd;
	(void)ta;

	memset(&req, 0x0, sizeof(req));

	ret = getrandom(req.iv, 16, 0);
	if (ret < 0) {
		PRINT("random fail %ld\n", ret);
		return -1;
	}

	fd = open("/dev/qce", O_RDWR | O_SYNC);
	if (fd < 0) {
		PRINT("open fail %d\n", fd);
		return -1;
	}

	in = alloc_dma_buf(fd);
	if (!in)
		return -1;

	out = alloc_dma_buf(fd);
	if (!out)
		return -1;

	req.alg = QCEDEV_ALG_AES;
	req.entries = 1;
	req.data_len = 16;
	req.encklen = 16;
	req.in_place_op = true;
	req.ivlen = 16;
	req.iv_ctr_size = 128;
	req.mode = QCEDEV_AES_MODE_CBC;
	req.op = QCEDEV_OFFLOAD_HLOS_HLOS;
	req.is_pattern_valid = false;
	memset(&req.pattern_info, 0, sizeof(req.pattern_info));
	req.vbuf.src[0].vaddr = (uint8_t *)in;
	req.vbuf.src[0].len = 16;
	req.vbuf.dst[0].vaddr = (uint8_t *)out;
	req.vbuf.dst[0].len = 16;
	req.encrypt = true;

	ret = ioctl(fd, QCEDEV_IOCTL_OFFLOAD_OP_REQ, &req);
	if (ret < 0) {
		PRINT("ioctl fail: %ld\n", ret);
		return -1;
	}

	close(fd);
	
	return 0;
}

int run_qce_test(void)
{
	struct ta test_ta;
	struct qcomtee_object *root, *client_env_object, *service_object;

	/* Get root + supplicant. */
	root = test_get_root();
	if (root == QCOMTEE_OBJECT_NULL) {
		PRINT("test_get_root.\n");
		return -1;
	}

	client_env_object = test_get_client_env_object(root);
	if (client_env_object == QCOMTEE_OBJECT_NULL) {
		PRINT("test_get_client_env_object.\n");
		return -1;
	}

	/* 3 is UID of App. Loader service. */
	service_object = test_get_service_object(client_env_object, 3);
	if (service_object == QCOMTEE_OBJECT_NULL) {
		PRINT("test_get_service_object.\n");
		return -1;
	}

	/* Load the TA. */
	test_ta = test_load_ta(service_object, "/lib/firmware/ta/");
	if (test_ta.ta == QCOMTEE_OBJECT_NULL) {
		PRINT("test_load_ta.\n");
		return -1;
	}

	/* Program key */
	if (set_key(test_ta.ta)) {
		PRINT("setting key failed\n");
		return -1;
	}

	/* Encrypt data */
	if (encrypt_data(test_ta.ta)) {
		PRINT("encrypting data failed\n");
		return -1;
	}

	PRINT("SUCCESS.\n");

	return 0;
}
