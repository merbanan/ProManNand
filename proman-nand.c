/*
 * ProMan nand command line software
 *
 * Copyright (C) 2019 iopsys Software Solutions AB. All rights reserved.
 *
 * Author: Benjamin Larsson <benjamin.larsson@iopsys.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

/*

Bus 001 Device 020: ID 05a9:7814 OmniVision Technologies, Inc. 
Device Descriptor:
  bLength                18
  bDescriptorType         1
  bcdUSB               2.00
  bDeviceClass            0 (Defined at Interface level)
  bDeviceSubClass         0 
  bDeviceProtocol         0 
  bMaxPacketSize0        64
  idVendor           0x05a9 OmniVision Technologies, Inc.
  idProduct          0x7814 
  bcdDevice            2.00
  iManufacturer           1 DianZiDaRen
  iProduct                2 ProMan In High Speed
  iSerial                 3 00000000001A
  bNumConfigurations      1
  Configuration Descriptor:
    bLength                 9
    bDescriptorType         2
    wTotalLength           32
    bNumInterfaces          1
    bConfigurationValue     1
    iConfiguration          0 
    bmAttributes         0xc0
      Self Powered
    MaxPower              200mA
    Interface Descriptor:
      bLength                 9
      bDescriptorType         4
      bInterfaceNumber        0
      bAlternateSetting       0
      bNumEndpoints           2
      bInterfaceClass         7 Printer
      bInterfaceSubClass      1 Printer
      bInterfaceProtocol      2 Bidirectional
      iInterface              0 
      Endpoint Descriptor:
        bLength                 7
        bDescriptorType         5
        bEndpointAddress     0x81  EP 1 IN
        bmAttributes            2
          Transfer Type            Bulk
          Synch Type               None
          Usage Type               Data
        wMaxPacketSize     0x0200  1x 512 bytes
        bInterval               0
      Endpoint Descriptor:
        bLength                 7
        bDescriptorType         5
        bEndpointAddress     0x01  EP 1 OUT
        bmAttributes            2
          Transfer Type            Bulk
          Synch Type               None
          Usage Type               Data
        wMaxPacketSize     0x0200  1x 512 bytes
        bInterval               0
Device Qualifier (for other device speed):
  bLength                10
  bDescriptorType         6
  bcdUSB               2.00
  bDeviceClass            7 Printer
  bDeviceSubClass         1 Printer
  bDeviceProtocol         2 Bidirectional
  bMaxPacketSize0        64
  bNumConfigurations      1
Device Status:     0x0001
  Self Powered

*/


#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>
#include <byteswap.h>
#include <unistd.h>
#include <libusb-1.0/libusb.h> 

#define VENDOR_ID 0x05a9
#define PRODUCT_ID 0x7814

#define BULK_EP_OUT     0x01
#define BULK_EP_IN      0x81

#define PACKET_CTRL_LEN 0x4

// HID Class-Specific Requests values. See section 7.2 of the HID specifications 
#define HID_GET_REPORT                0x01 
#define HID_GET_IDLE                  0x02 
#define HID_GET_PROTOCOL              0x03 
#define HID_SET_REPORT                0x09 
#define HID_SET_IDLE                  0x0A 
#define HID_SET_PROTOCOL              0x0B 
#define HID_REPORT_TYPE_INPUT         0x01 
#define HID_REPORT_TYPE_OUTPUT        0x02 
#define HID_REPORT_TYPE_FEATURE       0x03 

#define CTRL_IN      LIBUSB_ENDPOINT_IN |LIBUSB_REQUEST_TYPE_VENDOR|LIBUSB_RECIPIENT_INTERFACE
#define CTRL_OUT     LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_VENDOR|LIBUSB_RECIPIENT_INTERFACE

#define READ_ID                 86
#define READ_ID_LEN             8
#define FIRMWARE_VERSION        91
#define FIRMWARE_VERSION_LEN    4
#define BAD_BLOCK_LIST          87
#define BAD_BLOCK_LIST_LEN      8
#define STATUS            90
#define STATUS_LEN        8

const static int TIMEOUT=5000; /* timeout in ms */
#define TRANSFER_BUF_LEN 16384
uint8_t transfer_buffer[TRANSFER_BUF_LEN] = {0};

typedef struct {
    int verbose;
    const char* input_file;
    const char* output_file;
    FILE *in_file;
    FILE *out_file;
    struct libusb_device_handle *devh;

    // operation config
    int blocks;
    int read_offset;
    int write_offset;
    int spare_area;

    const char* manufacturer_str;
    //geometry
    int block_size;
    int page_size;
    int spare_area_size;
    int total_blocks;
    int geo_blocks;
    int pages_per_block;
} pm_ctx;


uint32_t swap_uint32( uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}


void print_usage(void) {
    printf("proman-nand version 1.2\n");
    printf("\t -S get reader and chip status\n");
    printf("\t -l blink reader leds\n");
    printf("\t -B get bad block list\n");
    printf("\t -E erase chip\n");
    printf("\t -h get help page\n");
    printf("\t -r <0xXXX> read data starting from offset (needs to be block aligned)\n");
    printf("\t -w <0xXXX> write data starting from offset (needs to be block aligned)\n");
    printf("\t -b <#> blocks to handle (used by -r and -w)\n");
    printf("\t -s handle spare area (used by -r and -w)\n");
    printf("\t -o <string> output file name\n");
    printf("\t -i <string> output file name\n");
    printf("\n\n");
    printf("example:\n./proman-nand -r 0x0 -b 8 -s -o tst.raw\n");
    printf("./proman-nand -w 0x0 -b 8 -s -i tst.raw\n");
    return;
}

int pm_blink_led(pm_ctx* q) {
    int i,r;
    int transferred = 0;
    unsigned char blink_led_cmd[] = {0x55, 0xaa, 0x5f, 0xcc, 0xcc, 0xcc, 0x66, 0xaa};
    int blink_led_cmd_len = 8;


    r = libusb_bulk_transfer(q->devh, BULK_EP_OUT, blink_led_cmd, blink_led_cmd_len, &transferred, 0);
    if (r < 0) {
        fprintf(stderr, "Control Out error %d\n", r);
        return r;
    }
    return r;
}

int pm_send_ctrl_in(pm_ctx* q, int request_type, uint8_t* buf, int buf_len) {
    int r,i;
    uint8_t tmp_buf[4] = {0};
    uint32_t* tmp;
    /* send request */
    r = libusb_control_transfer(q->devh, CTRL_IN, request_type, 0x0000, 0x00000, buf, buf_len, TIMEOUT);
    if (r < 0) {
        fprintf(stderr, "Urb control in error %d\n", r);
        return r;
    }
    /* Swap answer buffer */
    for (i=0 ; i<r ; i+=4) {
        tmp = (uint32_t*)&buf[i];
        *tmp = swap_uint32(*tmp);
    }
    return 1;
}

int pm_send_bulk_out(pm_ctx* q, uint8_t* bulk_cmd, int bulk_cmd_len) {
    int r;
    int transferred = 0;
    r = libusb_bulk_transfer(q->devh, BULK_EP_OUT, bulk_cmd, bulk_cmd_len, &transferred, 0);
    if (r < 0) {
        fprintf(stderr, "Bulk Out error %d\n", r);
        return r;
    }
    return r;
}

int pm_send_bulk_in(pm_ctx* q, uint8_t* buf, int buf_len) {
    int r;
    int transfered = 0;
    r = libusb_bulk_transfer(q->devh, BULK_EP_IN, buf, buf_len, &transfered, TIMEOUT);
    if (r < 0) {
        fprintf(stderr, "Bulk In error %d\n", r);
        return r;
    }
    return transfered;
}


void pm_fill_array(uint8_t* array, int idx, int value) {
    int offset = idx*4;
    array[offset+0] = (value&0x000000FF);
    array[offset+1] = (value&0x0000FF00) >> 8;
    array[offset+2] = (value&0x00FF0000) >> 16;
    array[offset+3] = (value&0xFF000000) >> 24;
};



int pm_read_id(pm_ctx* q) {
    int bs, sa, ps;
    uint8_t ans_buf[READ_ID_LEN] = {0};

    pm_send_ctrl_in(q, READ_ID, ans_buf, READ_ID_LEN);
    if (q->verbose) printf("READ_ID: %02x%02x%02x%02x%02x%02x%02x%02x\n", ans_buf[0], ans_buf[1], ans_buf[2], ans_buf[3], ans_buf[4], ans_buf[5], ans_buf[6], ans_buf[7]);


    /* parse chip vendor id data */
    switch (ans_buf[0]) {
        case 0xec:
        case 0x98:
            switch (ans_buf[1]) {
                case 0xf1:
                    q->geo_blocks=1024;
                    q->manufacturer_str="Samsung";
                case 0xd3:
                    q->geo_blocks=4096;
                    q->manufacturer_str="Toshiba";
                default:
                    break;
            }
    }
    /* populate geometry */
    ps = (ans_buf[3]&0x03);
    q->page_size = (1<<ps)*1024;
    bs = (ans_buf[3]&0x30)>>4;
    q->block_size = (1<<bs)*65536;
    sa = (ans_buf[3]&0x04)>>2;
    q->spare_area_size = (q->page_size/512) * ((1<<sa)*8);
    q->pages_per_block = q->block_size/q->page_size;

};

int pm_set_geometry(pm_ctx* q) {
    uint8_t ans_buf[STATUS_LEN] = {0};
    uint8_t set_geometry_cmd[] = {
    0x55, 0xaa, 0x5d, 0xcc, // Start command id
    0x00, 0x00, 0x00, 0x00, // page data size
    0x00, 0x00, 0x00, 0x00, // page spare size
    0x00, 0x00, 0x00, 0x00, // pages per block
    0x00, 0x00, 0x00, 0x00, // chip select count
    0x00, 0x00, 0x00, 0x00, // blocks per chip select
    0xcc, 0xcc, 0x66, 0xaa}; // end marker
    uint8_t set_geometry_cmd_len = 28;

    /* Get genometry by combining READID and table data */
    pm_read_id(q);

    /* Populate set geometry command */
    pm_fill_array(set_geometry_cmd, 1, q->page_size);
    pm_fill_array(set_geometry_cmd, 2, q->spare_area_size);
    pm_fill_array(set_geometry_cmd, 3, q->block_size/q->page_size); // pages per block
    pm_fill_array(set_geometry_cmd, 4, 1);  // default to only 1 chip select
    pm_fill_array(set_geometry_cmd, 5, q->geo_blocks);

    /* Send command */
    pm_send_bulk_out(q, set_geometry_cmd, set_geometry_cmd_len);

    /* Check status */
    pm_send_ctrl_in(q, STATUS, ans_buf, STATUS_LEN);
};

int pm_erase_chip(pm_ctx* q) {
    int i;
    uint8_t ans_buf[STATUS_LEN] = {0};
    int transferred = 0;
    uint8_t erase_chip_cmd[] = {0x55, 0xaa, 0x58, 0xcc, 0x01, 0x01, 0x66, 0xaa};
    int erase_chip_cmd_len = 8;
    int total_blocks, done_blocks, good_blocks;

    /* Get genometry by combining READID and table data */
    pm_set_geometry(q);

    /* Get total block amount */
    pm_send_bulk_out(q, erase_chip_cmd, erase_chip_cmd_len);
//    usleep(10000);  // not sure this is needed.
    pm_send_ctrl_in(q, STATUS, ans_buf, STATUS_LEN);
    total_blocks = (ans_buf[4] << 8) | ans_buf[5];
    done_blocks = (ans_buf[6] << 8) | ans_buf[7];

    while (done_blocks < total_blocks) {
        pm_send_bulk_out(q, erase_chip_cmd, erase_chip_cmd_len);
//        usleep(10000);
        pm_send_ctrl_in(q, STATUS, ans_buf, STATUS_LEN);
        done_blocks = (ans_buf[6] << 8) | ans_buf[7];
//        printf("Erase chip: %02x%02x%02x%02x%02x%02x%02x%02x\n", ans_buf[0], ans_buf[1], ans_buf[2], ans_buf[3], ans_buf[4], ans_buf[5], ans_buf[6], ans_buf[7]);
    }
    good_blocks = (ans_buf[0] << 8) | ans_buf[1];
    printf("ERASE_BLOCKS:\n");
    printf("Total blocks: %d\nTotal good blocks erased: %d\n", total_blocks, good_blocks);
}



int pm_hardware_version(pm_ctx* q) {
    uint8_t ans_buf[FIRMWARE_VERSION_LEN] = {0};

    pm_send_ctrl_in(q, FIRMWARE_VERSION, ans_buf, FIRMWARE_VERSION_LEN);
    printf("Firmware version: %02x%02x%02x%02x\n", ans_buf[0], ans_buf[1], ans_buf[2], ans_buf[3]);
};




void pm_get_status(pm_ctx* q) {

    pm_hardware_version(q);
    pm_read_id(q);

    printf("\nNand chip geometry:\n");
    printf("block_size: %d\npage_size %d\nspare_area_size %d\n", q->block_size, q->page_size, q->spare_area_size);
    printf("blocks: %d\n", q->geo_blocks);
    printf("manufacturer: %s\n", q->manufacturer_str);

    return;
};



int pm_read_bbl(pm_ctx* q) {
    int i,r;
    uint8_t ans_buf[BAD_BLOCK_LIST_LEN] = {0};
    int transferred = 0;
    uint8_t read_bbl_cmd[] = {0x55, 0xaa, 0x57, 0x01, 0xcc, 0xcc, 0x66, 0xaa};
    int read_bbl_cmd_len = 8;
    uint16_t bbl_entry1 = 0;
    uint16_t bbl_entry2 = 0;
    uint16_t bbl_tmp = 0;
    int cnt = 128;

    pm_set_geometry(q);

    pm_send_bulk_out(q, read_bbl_cmd, read_bbl_cmd_len);

    while ((bbl_tmp != 0xFFFF) && cnt) {
        pm_send_ctrl_in(q, BAD_BLOCK_LIST, ans_buf, BAD_BLOCK_LIST_LEN);

        bbl_tmp = ans_buf[2]<<8 | ans_buf[3];
        if ((bbl_tmp != 0xfffa) & (bbl_tmp != 0xffff)) printf("BBL: Block %d marked bad\n", bbl_tmp);
        bbl_tmp = ans_buf[0]<<8 | ans_buf[1];
        if ((bbl_tmp != 0xfffa) & (bbl_tmp != 0xffff)) printf("BBL: Block %d marked bad\n", bbl_tmp);
        bbl_tmp = ans_buf[6]<<8 | ans_buf[7];
        if ((bbl_tmp != 0xfffa) & (bbl_tmp != 0xffff)) printf("BBL: Block %d marked bad\n", bbl_tmp);
        bbl_tmp = ans_buf[4]<<8 | ans_buf[5];
        if ((bbl_tmp != 0xfffa) & (bbl_tmp != 0xffff)) printf("BBL: Block %d marked bad\n", bbl_tmp);

        cnt--;
    }
}


int pm_read_blocks(pm_ctx* q) {
    int i, r, ret = 1;
    uint8_t ans_buf[STATUS_LEN] = {0};
    int transferred = 0;
    int pages_per_block;
    int end_offset;
    int retry_cnt=10000;
    int bytes_to_read = 0, bytes_read = 0, bytes_in_bulk;
    int done_bytes;
//    uint8_t read_block1_cmd[] = {0x55, 0xaa, 0x5f, 0xcc, 0xcc, 0xcc, 0x66, 0xaa};
    int read_block1_cmd_len = 8;
    uint8_t read_block2_cmd[] = {0x55, 0xaa, 0x5a, 0xcc, 0x11, 0x11, 0x11, 0x11,
                                 0x22, 0x22, 0x22, 0x22, 0x01, 0x00, 0x00, 0x01,
                                 0xcc, 0xcc, 0x66, 0xaa};
    int read_block2_cmd_len = 20;

    pm_set_geometry(q);

    /* Reset device ? */
//    pm_send_bulk_out(devh, read_block1_cmd, read_block1_cmd_len);
//    pm_send_bulk_out(devh, read_block1_cmd, read_block1_cmd_len);

    /* Populate read data command */
    pm_fill_array(read_block2_cmd, 1, q->read_offset);

    end_offset = q->read_offset + (q->block_size * q->blocks) -1;
    pm_fill_array(read_block2_cmd, 2, end_offset);

    /* Read spare area */
    read_block2_cmd[13] = q->spare_area;
    /* Unknown, maybe selector between automatic or manual geometry ? */
    read_block2_cmd[14] = 1;

    if (!q->spare_area) q->spare_area_size = 0;
    
    bytes_to_read = q->blocks*(q->block_size + q->spare_area_size*q->pages_per_block);
    
    printf("end spare_area_size: %d\n", q->spare_area_size);
    printf("Bytes to read: %d\n", bytes_to_read);


    printf("end offset: %x\n", end_offset);
    printf("Read blocks: %02x %02x %02x %02x %02x %02x %02x %02x\n", read_block2_cmd[4], read_block2_cmd[5], read_block2_cmd[6], read_block2_cmd[7], read_block2_cmd[8], read_block2_cmd[9], read_block2_cmd[10], read_block2_cmd[11]);
    printf("Control bytes: %02x %02x %02x %02x\n", read_block2_cmd[12], read_block2_cmd[13], read_block2_cmd[14], read_block2_cmd[15]);

    pm_send_bulk_out(q, read_block2_cmd, read_block2_cmd_len);

    printf("\n");

    while (pm_send_ctrl_in(q, STATUS, ans_buf, STATUS_LEN) && (bytes_read < bytes_to_read) && retry_cnt--) {
        if (q->verbose) printf("READ_BLOCK: %02x%02x%02x%02x\n", ans_buf[0], ans_buf[1], ans_buf[2], ans_buf[3]);
        done_bytes = (ans_buf[4] << 24) | (ans_buf[5] << 16) | (ans_buf[6] << 8) | ans_buf[7];
        if (q->verbose) printf("READ_BLOCK: bytes done=%d\n", done_bytes);
        if (ans_buf[1] == 0x12) {
            int buffer_size = TRANSFER_BUF_LEN;
            /* Data ready for reading*/
//            printf("SENDING BULK_IN:\n");
            if ((bytes_to_read - bytes_read) < TRANSFER_BUF_LEN)
                 buffer_size=bytes_to_read - bytes_read;
            bytes_in_bulk = pm_send_bulk_in(q, transfer_buffer, buffer_size);
            bytes_read+=bytes_in_bulk;
//            printf("BULK_IN: read size=%d < bytes_to_read=%d %d\n", bytes_read, bytes_to_read, bytes_in_bulk);
            fwrite(transfer_buffer, bytes_in_bulk, 1, q->out_file);
        } else if (ans_buf[1] == 0x3b){
            /* Data not ready for reading, wait a while */
            usleep(100000);
        } else {
            /* Unknown error, abort */
//            return -1;
        }
    }
    pm_send_ctrl_in(q, STATUS, ans_buf, STATUS_LEN);
    done_bytes = (ans_buf[4] << 24) | (ans_buf[5] << 16) | (ans_buf[6] << 8) | ans_buf[7];
    printf("READ_BLOCK: bytes done=%d\n", done_bytes);

//    printf("READ_BLOCK: %02x%02x%02x%02x%02x%02x%02x%02x\n", ans_buf[0], ans_buf[1], ans_buf[2], ans_buf[3], ans_buf[4], ans_buf[5], ans_buf[6], ans_buf[7]);

    /* get the leds back in order */
    pm_blink_led(q);
    pm_blink_led(q);
    return ret;
}


int pm_write_blocks(pm_ctx* q) {

    int i, r, ret = 1;
    uint8_t ans_buf[STATUS_LEN] = {0};
    int transferred = 0;

    int end_offset;
    int fail_cnt=10000;
    int bytes_to_write = 0, bytes_written = 0, bytes_in_bulk;
    int done_bytes;
    uint32_t *tmp;
    int retry_cnt=100000;

    uint8_t write_block_cmd[] = {0x55, 0xaa, 0x59, 0xcc, 0x11, 0x11, 0x11, 0x11,
                                 0x22, 0x22, 0x22, 0x22, 0xcc, 0x00, 0x01, 0x01,
                                 0x01, 0xcc, 0x66, 0xaa};
    int write_block_cmd_len = 20;

    pm_set_geometry(q);

    pm_fill_array(write_block_cmd, 1, q->write_offset);

    q->pages_per_block = q->block_size/q->page_size;
    end_offset = q->write_offset + ((q->block_size+q->spare_area_size*q->pages_per_block) * q->blocks);

    pm_fill_array(write_block_cmd, 2, end_offset);


    /* Write spare area ?*/
    write_block_cmd[13] = q->spare_area;

    printf("Write blocks: %02x %02x %02x %02x %02x %02x %02x %02x\n", write_block_cmd[4], write_block_cmd[5], write_block_cmd[6], write_block_cmd[7], write_block_cmd[8], write_block_cmd[9], write_block_cmd[10], write_block_cmd[11]);
    printf("Control bytes: %02x %02x %02x %02x\n", write_block_cmd[12], write_block_cmd[13], write_block_cmd[14], write_block_cmd[15]);

    pm_send_bulk_out(q, write_block_cmd, write_block_cmd_len);
    pm_send_ctrl_in(q, STATUS, ans_buf, STATUS_LEN);
    tmp = (uint32_t*)&ans_buf[4];
    printf("WRITE_BLOCK: bytes written=%x\n", *tmp);

    if (!q->spare_area) q->spare_area_size = 0;
    bytes_to_write = q->blocks*(q->block_size + q->spare_area_size*q->pages_per_block);
    printf("WRITE_BLOCK: bytes to write %d\n", bytes_to_write);


    while (1 /*pm_send_ctrl_in(q, STATUS, ans_buf, STATUS_LEN) && retry_cnt--*/) {
        int buffer_size;
        buffer_size = fread(transfer_buffer, 1, TRANSFER_BUF_LEN, q->in_file);
        if (q->verbose) printf("WB: buffer_size=%d\n", buffer_size);
        if (!buffer_size) break;
        usleep(10000);
        bytes_in_bulk = pm_send_bulk_out(q, transfer_buffer, buffer_size);
    }

    pm_send_ctrl_in(q, STATUS, ans_buf, STATUS_LEN);
    tmp = (uint32_t*)&ans_buf[4];
    printf("WRITE_BLOCK: bytes written=%x\n", *tmp);
}

int main(int argc, char** argv)
{
    int verbose = 0;
    int probe = 0;
	int option = 0;
	int blink_led = 0;
    int read_id = 0;
    int read_bbl = 0;
    int erase_chip = 0;
    int read = 0, write = 0;

    int get_status = 0;
    int r;
    pm_ctx p = {0};
    pm_ctx* q = &p; 

    while ((option = getopt(argc, argv,"EBhvlr:b:si:o:w:S")) != -1) {
        switch (option) {
            case 'i' : q->input_file = optarg;
                break;
            case 'o' : q->output_file = optarg;
                break;
            case 'v': q->verbose = 1;
                break;
            case 'l': blink_led = 1;
                break;
            case 'B': read_bbl = 1;
                break;
            case 'E': erase_chip = 1;
                break;
            case 'r': q->read_offset = strtol(optarg, NULL, 16); read = 1;
                break;
            case 'w': q->write_offset = strtol(optarg, NULL, 16); write = 1;
                break;
            case 'b': q->blocks = atoi(optarg);
                break;
            case 's': q->spare_area = 1;
                break;
            case 'S': get_status = 1; q->verbose=1;
                break;
            case 'h':
            default: print_usage(); 
                 exit(EXIT_FAILURE);
        }
    }

    /* Init USB */
    r = libusb_init(NULL); 
    if (r < 0) { 
        fprintf(stderr, "Failed to initialise libusb\n"); 
        exit(1); 
    }

    q->devh = libusb_open_device_with_vid_pid(NULL, VENDOR_ID, PRODUCT_ID);
	if (!q->devh) {
        if (q->verbose) fprintf(stderr, "Could not find/open ProMan device\n");
        goto end;
    }

    if (q->verbose) fprintf(stdout, "Successfully found the ProMan device\n"); 

    r = libusb_claim_interface(q->devh, 0); 
    if (r < 0) { 
        fprintf(stderr, "libusb_claim_interface error %d, trying to detach kernel driver\n", r);

        /* Claim failed, try with detaching kernel driver */
	    r = libusb_detach_kernel_driver (q->devh, 0);
        if (r < 0) {
            if (q->verbose) fprintf(stderr, "libusb_detach_kernel_driver error %d\n", r);
        }

        r = libusb_claim_interface(q->devh, 0);
        if (r < 0) {
            fprintf(stderr, "libusb_claim_interface error %d\n", r);
            goto end;
        }
    }

    /* Command line options */

    if (blink_led) pm_blink_led(q);

    if (read_bbl)  pm_read_bbl(q);

    if (get_status)  pm_get_status(q);

    if (erase_chip) {
        pm_erase_chip(q);
        goto end;
    }


    /* I/O */

    if (read) {
        if (q->output_file == NULL) {
            printf("-o output file name is missing\n");
            goto end;
        }
        q->out_file = fopen(q->output_file,"wb");
        if (q->out_file == NULL) {
            printf("Out file open error\n");
            goto end;
        }

        pm_read_blocks(q);
        goto end;
    }

    if (write) {
        if (q->input_file == NULL) {
            printf("-i input file name is missing\n");
            goto end;
        }
        q->in_file = fopen(q->input_file,"r");
        if (q->in_file == NULL) {
            printf("In file open error\n");
            goto end;
        }
        pm_write_blocks(q);
    }


end:
    libusb_release_interface(q->devh, 0); 
 
    // libusb_reset_device(devh); 
    libusb_close(q->devh); 
    libusb_exit(NULL); 
exit:
    return r >= 0 ? r : -r; 
}
