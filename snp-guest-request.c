#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <string.h>
#include <errno.h>
#include <sys/random.h>

#include "psp-sev.h"
#include "sev-guest.h"

struct snp_report_data {
	uint32_t	version;
	uint32_t	guest_svn;
	uint64_t	policy;
	uint8_t		family_id[16];
	uint8_t		image_id[16];
	uint32_t	vmpl;
	uint32_t	sig_algo;
	uint64_t	plat_version;
	uint64_t	plat_info;
	uint32_t	author_key_en;
	uint32_t	rsvd1;
	uint8_t		report_data[64];
	uint8_t		measurement[48];
	uint8_t		host_data[32];
	uint8_t		id_key_digest[48];
	uint8_t		author_key_digest[48];
	uint8_t		report_id[32];
	uint8_t		report_id_ma[32];
	uint64_t	reported_tcb;
	uint8_t		rsvd2[78];
	uint8_t		chip_id[64];
};

struct snp_report_response_data {
	uint32_t	status;
	uint32_t	size;
	uint8_t		rsvd[18];
	struct snp_report_data report;
};

struct snp_derive_key_response_data {
	uint32_t	status;
	uint8_t		rsvd[28];
	uint8_t		key[32];
};

static void print_hex_dump(const char *prefix, uint8_t *buf, uint32_t len)
{
	uint32_t i;
	char spaces[80] = {};

	memset(spaces, ' ', strlen(prefix));

	printf("%s", prefix);

	for (i = 0; i < len; i++) {
		if (i && (i % 16) == 0)
			printf("\n%s", spaces);
		printf("%02hhx ", buf[i]);
	}
	printf("\n");

}

static void dump_report(struct snp_report_response_data *resp)
{
	printf("Attestation Report (%d bytes)\n", resp->size);
	printf(" version          : %d\n", resp->report.version);
	printf(" guest_svn        : %d\n", resp->report.guest_svn);
	printf(" policy           : 0x%lx\n", resp->report.policy);
	print_hex_dump(" family_id        : ", resp->report.family_id, sizeof(resp->report.family_id));
	print_hex_dump(" image_id         : ", resp->report.image_id, sizeof(resp->report.image_id));
	printf(" vmpl             : %d\n", resp->report.vmpl);
	printf(" sig_algo         : %d\n", resp->report.sig_algo);
	printf(" plat_version     : 0x%lx\n", resp->report.plat_version);
	printf(" plat_info        : 0x%lx\n", resp->report.plat_info);
	printf(" author_key_en    : %d\n", resp->report.author_key_en);
	print_hex_dump(" report_data      : ", resp->report.report_data, sizeof(resp->report.report_data));
	print_hex_dump(" measurement      : ", resp->report.measurement, sizeof(resp->report.measurement));
	print_hex_dump(" host_data        : ", resp->report.host_data, sizeof(resp->report.host_data));
	print_hex_dump(" id_key_digest    : ", resp->report.id_key_digest, sizeof(resp->report.id_key_digest));
	print_hex_dump(" author_key_digest: ", resp->report.author_key_digest, sizeof(resp->report.author_key_digest));
	print_hex_dump(" report_id        : ", resp->report.report_id, sizeof(resp->report.report_id));
	print_hex_dump(" report_id_ma     : ", resp->report.report_id_ma, sizeof(resp->report.report_id_ma));
	printf(" reported_tcb     : 0x%lx\n", resp->report.reported_tcb);
	print_hex_dump(" chip_id          : ", resp->report.chip_id, sizeof(resp->report.chip_id));

}

int main(int argc, char **argv)
{
	struct snp_user_guest_request input = {};
	struct snp_report_req report_req;
	struct snp_report_resp report_resp;
	struct snp_report_response_data *resp;
	struct snp_derived_key_req key_req = {};
	struct snp_derived_key_resp key_resp;
	struct snp_derive_key_response_data *_key_resp;
	struct snp_ext_report_req ext_report_req = {};

	int fd, ret;

	fd = open("/dev/sev-guest", O_RDWR);
	if (fd < 0) {
		perror("/dev/sev-guest");
		exit(1);
	}

	report_req.msg_version = 1;
	getrandom(&report_req.user_data, 64, 0);

	input.req_data = (unsigned long)&report_req;
	input.resp_data = (unsigned long)&report_resp;

	printf("Request:\n");
	printf(" version      : %d\n", report_req.msg_version);
	print_hex_dump(" random data  : ", report_req.user_data, 64);

	ret = ioctl(fd, SNP_GET_REPORT, &input);
	if (ret) {
		printf("ioctl() %d %s fw_err=%llx\n", ret, strerror(errno), input.fw_err);
		exit(1);
	}

	resp = (struct snp_report_response_data *)&report_resp.data;

	if (!resp->status) {
		dump_report(resp);
	} else {
		printf("** failed to get the report\n");
	}

	key_req.msg_version = 1;
	input.req_data = (unsigned long)&key_req;
	input.resp_data = (unsigned long)&key_resp;

	ret = ioctl(fd, SNP_GET_DERIVED_KEY, &input);
	if (ret) {
		printf("ioctl() %d %s\n", ret, strerror(errno));
		exit(1);
	}

	_key_resp = (struct snp_derive_key_response_data*)&key_resp.data;
	if (!_key_resp->status) {
		printf("\n Derived key:\n");
		print_hex_dump("  ", _key_resp->key, sizeof(_key_resp->key));
	} else {
		printf("*** failed to derive key\n");
	}

	ext_report_req.data.msg_version = 1;
	getrandom(&ext_report_req.data.user_data, 64, 0);
	ext_report_req.certs_len = 4096;
	ext_report_req.certs_address = (unsigned long)malloc(ext_report_req.certs_len + 1);

	input.req_data = (unsigned long)&ext_report_req;
	input.resp_data = (unsigned long)&report_resp;

	printf("Ext Request:\n");
	printf(" version      : %d\n", ext_report_req.data.msg_version);
	print_hex_dump(" random data  : ", ext_report_req.data.user_data, 64);

	ret = ioctl(fd, SNP_GET_EXT_REPORT, &input);
	if (ret) {
		printf("ioctl() %d %s fw_err=%llx\n", ret, strerror(errno), input.fw_err);
		exit(1);
	}

	resp = (struct snp_report_response_data *)&report_resp.data;

	if (!resp->status) {
		dump_report(resp);
	} else {
		printf("** failed to get the report\n");
	}
	print_hex_dump("certs data :", (uint8_t *)ext_report_req.certs_address, ext_report_req.certs_len);

	close(fd);
	return 0;
}
