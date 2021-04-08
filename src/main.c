/*
 * PS Vita shell dolce style
 * Copyright (C) 2021
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <psp2/kernel/modulemgr.h>
#include <taihen.h>

#define BUBBLE_SIZE (108.0f)

int get_movt_opcode(void *dst, unsigned int target_reg, uint16_t val){

	if(dst == NULL)
		return -1;

	if(target_reg > 0xF)
		return -2;

	((uint8_t *)dst)[0] = ((val >> 0xC) & 0xF) | 0xC0;
	((uint8_t *)dst)[1] = ((val & 0x800) != 0) ? 0xF6 : 0xF2;
	((uint8_t *)dst)[2] = val & 0xFF;
	((uint8_t *)dst)[3] = (((val & ~0x800) & 0xF00) >> 4) | target_reg;

	return 0;
}

uint16_t __attribute__((noinline, naked)) getFloatUpper16(float value){
	__asm__ volatile(
		"mvns r0, #0x0\n"
		"vmov r1, s0\n"
		"lsls r0, #16\n"
		"ands r1, r0\n"
		"lsrs r0, r1, #16\n"
		"bx lr\n"
		::: "r0", "r1"
	);
}

tai_hook_ref_t sceShellGetBubbleSize1_ref;
void sceShellGetBubbleSize1_patch(void *a1){

	TAI_CONTINUE(void, sceShellGetBubbleSize1_ref, a1);

	void *ptr = *(void **)(a1);
	if(ptr != NULL){
		ptr = *(void **)(ptr + 0x220);
		if(ptr != NULL){
			*(float *)(ptr + 0x48) = BUBBLE_SIZE + 60.0f;
			*(float *)(ptr + 0x4C) = BUBBLE_SIZE + 60.0f;
		}
	}

	return;
}

tai_hook_ref_t sceShellGetBubbleSize2_ref;
void sceShellGetBubbleSize2_patch(void *a1){

	TAI_CONTINUE(void, sceShellGetBubbleSize2_ref, a1);

	void *ptr = *(void **)(a1);
	if(ptr != NULL){
		ptr = *(void **)(ptr + 0x220);
		if(ptr != NULL){
			*(float *)(ptr + 0x48) = BUBBLE_SIZE + 60.0f;
			*(float *)(ptr + 0x4C) = BUBBLE_SIZE + 60.0f;
		}
	}

	return;
}

tai_hook_ref_t sceShellGetBubbleSize3_ref;
float sceShellGetBubbleSize3_patch(void){
	// We are cannot call original function
	// TAI_CONTINUE(float, sceShellGetBubbleSize3_ref);
	return BUBBLE_SIZE;
}

tai_hook_ref_t sceShellGetBubbleSize4_ref;
float sceShellGetBubbleSize4_patch(void){
	// We are cannot call original function
	// TAI_CONTINUE(float, sceShellGetBubbleSize4_ref);
	return BUBBLE_SIZE;
}

#define HookOffset(modid, offset, thumb, func_name) \
	taiHookFunctionOffset(&func_name ## _ref, modid, 0, offset, thumb, func_name ## _patch)

void _start() __attribute__ ((weak, alias("module_start")));
int module_start(SceSize args, void *argp){

	tai_module_info_t info;
	info.size = sizeof(info);

	if(taiGetModuleInfo("SceShell", &info) < 0)
		return SCE_KERNEL_START_FAILED;

	SceUInt32 offset_reset, offset_func, offset_status;

	switch(info.module_nid){
	case 0x0552F692: // Retail 3.60
		offset_status = 0x15C258 + 8;
		offset_reset  = 0xBBFB8 + 0x1A;
		offset_func   = 0xBBCCA;
		break;
	case 0x6CB01295: // Devkit 3.60
		offset_status = 0x153C90 + 8;
		offset_reset  = 0xB8738 + 0x1A;
		offset_func   = 0xB844A;
		break;
	case 0x5549BF1F: // Retail 3.65
		offset_status = 0x15C2B0 + 8;
		offset_reset  = 0xBC010 + 0x1A;
		offset_func   = 0xBBD22;
		break;
	default:
		return SCE_KERNEL_START_FAILED;
		break;
	}

	int opcode;

	// Status bar
	opcode = 0x2001BF00;
	taiInjectData(info.modid, 0, offset_status, &opcode, 4);

	get_movt_opcode(&opcode, 1, getFloatUpper16(BUBBLE_SIZE));

	// Patch to sceShellResetBubbleInfo
	taiInjectData(info.modid, 0, offset_reset, &opcode, 4);

	offset_reset += 0x12;
	taiInjectData(info.modid, 0, offset_reset, &opcode, 4);

	// Hook to getBubbleSize functions
	HookOffset(info.modid, offset_func, 1, sceShellGetBubbleSize1);

	offset_func += 0x8E;
	HookOffset(info.modid, offset_func, 1, sceShellGetBubbleSize2);

	offset_func += 0xDC;
	HookOffset(info.modid, offset_func, 1, sceShellGetBubbleSize3);

	offset_func += 0x22;
	HookOffset(info.modid, offset_func, 1, sceShellGetBubbleSize4);

	return SCE_KERNEL_START_SUCCESS;
}
