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
//#define BULK_EP_IN      0x08

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
#define ERASE_STATUS            90
#define ERASE_STATUS_LEN        8

const static int TIMEOUT=5000; /* timeout in ms */

uint32_t swap_uint32( uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}


void print_usage(void) {
    printf("proman-nand version 1.0\n");     

    return;
}

int pm_blink_led(struct libusb_device_handle *devh) {
    int i,r;
    int transferred = 0;
    unsigned char blink_led_cmd[] = {0x55, 0xaa, 0x5f, 0xcc, 0xcc, 0xcc, 0x66, 0xaa};
    int blink_led_cmd_len = 8;


    r = libusb_bulk_transfer(devh, BULK_EP_OUT, blink_led_cmd, blink_led_cmd_len, &transferred, 0);
    if (r < 0) {
        fprintf(stderr, "Control Out error %d\n", r);
        return r;
    }
    return r;
}

int pm_send_ctrl_in(struct libusb_device_handle *devh, int request_type, uint8_t* buf, int buf_len) {
    int r,i;
    uint8_t tmp_buf[4] = {0};
    uint32_t* tmp;
    /* send request */
    r = libusb_control_transfer(devh, CTRL_IN, request_type, 0x0000, 0x00000, buf, buf_len, TIMEOUT);
    if (r < 0) {
        fprintf(stderr, "Urb control in error %d\n", r);
        return r;
    }
    /* Swap answer buffer */
    for (i=0 ; i<r ; i+=4) {
        tmp = (uint32_t*)&buf[i];
        *tmp = swap_uint32(*tmp);
    }
}

int pm_send_bulk_out(struct libusb_device_handle *devh, uint8_t* bulk_cmd, int bulk_cmd_len) {
    int r;
    int transferred = 0;
    r = libusb_bulk_transfer(devh, BULK_EP_OUT, bulk_cmd, bulk_cmd_len, &transferred, 0);
    if (r < 0) {
        fprintf(stderr, "Bulk Out error %d\n", r);
        return r;
    }
    return r;
}


int pm_read_bbl(struct libusb_device_handle *devh) {
    int i,r;
    uint8_t ans_buf[BAD_BLOCK_LIST_LEN] = {0};
    int transferred = 0;
    uint8_t read_bbl_cmd[] = {0x55, 0xaa, 0x57, 0x00, 0xcc, 0xcc, 0x66, 0xaa};
    int read_bbl_cmd_len = 8;
    uint16_t bbl_entry1 = 0;
    uint16_t bbl_entry2 = 0;
    uint16_t bbl_tmp = 0;
    int cnt = 128;

    pm_send_bulk_out(devh, read_bbl_cmd, read_bbl_cmd_len);

    while ((bbl_tmp != 0xFFFF) && cnt) {
        pm_send_ctrl_in(devh, BAD_BLOCK_LIST, ans_buf, BAD_BLOCK_LIST_LEN);

        bbl_tmp = ans_buf[2]<<8 | ans_buf[3];
        if ((bbl_tmp != 0xfffa) & (bbl_tmp != 0xffff)) printf("BBL: Block %d marked bad\n", bbl_tmp);
        bbl_tmp = ans_buf[0]<<8 | ans_buf[1];
        if ((bbl_tmp != 0xfffa) & (bbl_tmp != 0xffff)) printf("BBL: Block %d marked bad\n", bbl_tmp);

        cnt--;
    }
}


int pm_erase_chip(struct libusb_device_handle *devh) {
    int i;
    uint8_t ans_buf[BAD_BLOCK_LIST_LEN] = {0};
    int transferred = 0;
    uint8_t erase_chip_cmd[] = {0x55, 0xaa, 0x58, 0xcc, 0x00, 0x00, 0x66, 0xaa};
    int erase_chip_cmd_len = 8;
    int total_blocks, done_blocks, good_blocks;

    /* Get total block amount */
    pm_send_bulk_out(devh, erase_chip_cmd, erase_chip_cmd_len);
//    usleep(10000);  // not sure this is needed.
    pm_send_ctrl_in(devh, ERASE_STATUS, ans_buf, ERASE_STATUS_LEN);
    total_blocks = (ans_buf[4] << 8) | ans_buf[5];
    done_blocks = (ans_buf[6] << 8) | ans_buf[7];

    while (done_blocks < total_blocks) {
        pm_send_bulk_out(devh, erase_chip_cmd, erase_chip_cmd_len);
//        usleep(10000);
        pm_send_ctrl_in(devh, ERASE_STATUS, ans_buf, ERASE_STATUS_LEN);
        done_blocks = (ans_buf[6] << 8) | ans_buf[7];
//        printf("Erase chip: %02x%02x%02x%02x%02x%02x%02x%02x\n", ans_buf[0], ans_buf[1], ans_buf[2], ans_buf[3], ans_buf[4], ans_buf[5], ans_buf[6], ans_buf[7]);
    }
    good_blocks = (ans_buf[0] << 8) | ans_buf[1];
    printf("ERASE_BLOCKS:\n");
    printf("Total blocks: %d\nTotal good blocks erased: %d\n", total_blocks, good_blocks);
}


int pm_hardware_version(struct libusb_device_handle *devh) {
    int i,r;
    uint8_t ans_buf[FIRMWARE_VERSION_LEN] = {0};

    pm_send_ctrl_in(devh, FIRMWARE_VERSION, ans_buf, FIRMWARE_VERSION_LEN);
    printf("Firmware version: %02x%02x%02x%02x\n", ans_buf[0], ans_buf[1], ans_buf[2], ans_buf[3]);
};


int pm_read_id(struct libusb_device_handle *devh) {
    int i,r;
    uint8_t ans_buf[READ_ID_LEN] = {0};

    pm_send_ctrl_in(devh, READ_ID, ans_buf, READ_ID_LEN);
    printf("READ_ID: %02x%02x%02x%02x%02x%02x%02x%02x\n", ans_buf[0], ans_buf[1], ans_buf[2], ans_buf[3], ans_buf[4], ans_buf[5], ans_buf[6], ans_buf[7]);
};


int main(int argc, char** argv)
{
    int verbose = 0;
    int probe = 0;
	int option = 0;
	int blink_led = 0;
    int read_id = 0;
    int read_bbl = 0;
    int erase_chip = 0;
    int r;
    struct libusb_device_handle *devh = NULL;

    while ((option = getopt(argc, argv,"EBhvdli")) != -1) {
        switch (option) {
            case 'v': verbose = 1;
                break;
            case 'd':  probe = 1;
                break;
            case 'l': blink_led = 1;
                break;
            case 'i': read_id = 1;
                break;
            case 'B': read_bbl = 1;
                break;
            case 'E': erase_chip = 1;
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

    devh = libusb_open_device_with_vid_pid(NULL, VENDOR_ID, PRODUCT_ID);
	if (!devh) {
        if (verbose) fprintf(stderr, "Could not find/open ProMan device\n");
        goto out;
    }

    if (verbose) fprintf(stdout, "Successfully found the ProMan device\n"); 

    r = libusb_claim_interface(devh, 0); 
    if (r < 0) { 
        fprintf(stderr, "libusb_claim_interface error %d, trying to detach kernel driver\n", r);

        /* Claim failed, try with detaching kernel driver */
	    r = libusb_detach_kernel_driver (devh, 0);
        if (r < 0) {
            if (verbose) fprintf(stderr, "libusb_detach_kernel_driver error %d\n", r);
        }

        r = libusb_claim_interface(devh, 0);
        if (r < 0) {
            fprintf(stderr, "libusb_claim_interface error %d\n", r);
            goto out;
        }
    }

    /* Command line options */

    if (blink_led) pm_blink_led(devh);

    if (probe) pm_hardware_version(devh);

    if (read_id) pm_read_id(devh);

    if (read_bbl) pm_read_bbl(devh);

    if (erase_chip) {
        pm_read_id(devh);   // This might be needed for the programmer to understand chip geometry
        pm_erase_chip(devh);
    }

    libusb_release_interface(devh, 0); 
out: 
    // libusb_reset_device(devh); 
    libusb_close(devh); 
    libusb_exit(NULL); 
exit:
    return r >= 0 ? r : -r; 
}
