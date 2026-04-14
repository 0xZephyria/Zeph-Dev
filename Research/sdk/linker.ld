ENTRY(_start)
SECTIONS
{
    . = 0x00000000;
    .text : {
        *(.text)
    }
    .rodata : {
        *(.rodata)
        *(.rodata.*)
    }

    . = 0x00010000;
    .data : {
        *(.data)
        *(.data.*)
        *(.sdata)
    }
    .bss : {
        *(.bss)
        *(.sbss)
    }
}
