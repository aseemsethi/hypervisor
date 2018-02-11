/*
 * MSRs: If bit 55 in the IA32_VMX_BASIC MSR is read as 0, all information 
 * about the allowed settings of the pin-based VM-execution controls is 
 * contained in the IA32_VMX_PINBASED_CTLS MSR. The pin controls are deined in 
 * Section 24.6.1. e.g. 
 * Bit0 - External Int exit - if "1", external int cause VM exits
 * Bit3 - NMI exit - if "1", NMI cause VM exit
 * Bits 31:0 indicate the allowed 0-settings of these controls. VM entry allows 
 * control X (bit X of the pin-based VM-execution controls) to be 0 if bit X 
 * in the MSR is cleared to 0.
 * Bits 63:32 indicate the allowed 1-settings of these controls. VM entry allows
 * control X to be 1 if bit 32+X in the MSR is set to 1; if bit 32+X in the MSR
 * is cleared to 0, VM entry fails if control X is 1.
 * Ref: A3.1 Intel Arch
 */

