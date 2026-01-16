---
title: "Harnessing Libraries for Effective Fuzzing"
date: 2026-01-15T13:45:02+01:00
draft: false
weight: 2
---

# Harnessing Libraries for Effective Fuzzing

## Introduction

Every security researcher or fuzzer enthusiast dreams of a program that takes a file as input, achieves deep coverage, and executes with lightning speed. Unfortunately, in the real world, only a handful of targets meet this ideal, making it unwise to "dumb fuzz" them (and you shouldn't! See this guide).

Most targets are not fuzzable out of the box and require you, the researcher, to do some heavy lifting to enable efficient fuzzing. In this article, we will explore how to fuzz a library, from the basics to persistent mode. Our focus will be on Freetype, a widely used software library for accessing font file contents.

Fuzzing a library can be summarized into these crucial steps:

1. Instrumenting the library
2. Studying the documentation
3. Identifying interesting functions
4. Writing a harness
5. Writing specific harnesses

## Instrumenting the Library

Instrumentation involves modifying a program's binary or source code to insert tracking and monitoring mechanisms. These additions help the fuzzer collect meaningful coverage information, guiding the fuzzing process. Instrumentation enables AFL++ to identify which code paths are executed during fuzzing, allowing for more intelligent and efficient exploration of the program's execution paths. AFL++ offers multiple instrumentation options; `afl-clang-fast` offers the possibility to be compatible with hongfuzz and libfuzzer and is also easier to debug than `afl-clang-lto`.

### Installing AFL++

The installation instructions can be found [here](https://github.com/AFLplusplus/AFLplusplus). First start by installing LLVM, then you can proceed to install AFL++.

### Compiling a Target Library

The process of compiling a library can be more or less complex depending on the target. In this exercise, Freetype compilation is a straightforward process.

If everything works correctly you will end up with multiple `.a` files composing the actual library.

### Testing the Library

In order to verify everything went correctly, let's write a small harness. First we check the Freetype documentation page and find a tutorial which describes the basic steps to use the library. Following this guide we are going to write this very minimalist harness.

We can now compile our target with the following command:

If everything goes well, you will end up with `test.elf` file that you can fuzz. You can try to fuzz it by running: `afl-fuzz -i inputs -o output -- ./test @@`

Congratulations, you've successfully harnessed a library! However, this program doesn't do much, does it? In fact, what we wrote is unlikely to uncover new bugs. Freetype, being a library that has undergone extensive testing, is less likely to have memory issues in such a basic function (unless…?). Now it's time to write a more advanced harness—one that stands a real chance of discovering new bugs!

## Going Through the Documentation

Reading the documentation of a library or software can often feel tedious. It's frequently overlooked because, after all: a few days of debugging can save you the trouble of reading a few pages of documentation, right? Jokes aside, if you aim to fuzz a specific library or program, you must be willing to learn about it. The strategy of blindly throwing a dumb fuzzer at any target without dedicating time and effort to understanding the target has proven highly inefficient in modern times.

When writing a harness for a library, it is crucial to understand what the library does. Ask yourself:

- What are its main purposes?
- What are its primary features?
- How does it process inputs?
- What are the library's internal mechanisms?
- Which features handle user inputs?

This stage is about gaining an initial understanding of the library—its main components, capabilities, and the areas worth fuzzing. In the main documentation for Freetype, we find the FAQ section, which contains a link to the page "What is Freetype?".

### What is FreeType?

Freetype is:

> "It is a software library that can be used by all kinds of applications to access the contents of font files. Most notably, it supports the following features:
>
> - It provides a uniform interface to access font files. It supports both bitmap and scalable formats, including TrueType, OpenType, Type1, CID, CFF, Windows FON/FNT, X11 PCF, and others.
> - It supports high-speed, anti-aliased glyph bitmap generation with 256 gray levels.
> - It is extremely modular, each font format being supported by a specific module. A build of the library can be tailored to support only the formats you need, thus reducing code size. A minimal anti-aliasing build of FreeType can be less than 30kByte."

The documentation also describes what FreeType is not:

> FreeType doesn't try to perform a number of sophisticated things, because it focuses on being an excellent font service. This means that the following features are not supported directly by the library:
>
> - rendering glyphs to arbitrary surfaces
> - glyph caching
> - text layout

This gives us a basic idea of what FreeType does. Let's dig a bit deeper in the documentation and read the Design section.

### FreeType Design

The documentation describes FreeType as a collection of components where each of them is in charge of one specific task.

Client applications typically call the FreeType 2 high-level API, whose functions are implemented in a single component called the Base Layer.

Depending on the context or the task, the base layer then calls one or more module components to perform the work. In most cases, the client application doesn't need to know which module was called.

The base layer also contains a set of routines that are used for generic things like memory allocation, list processing, I/O stream parsing, fixed-point computation, etc. These functions can also be called by a module at any time, and they form what is called the low-level base API.

#### Internal Objects and Classes

In this section is described the memory management and input stream basic mechanisms of FreeType. Here below are a few interesting pieces of information extracted from the documentation:

Most memory management operations are performed through three specific routines of the base layer: `FT_Alloc`, `FT_Realloc`, and `FT_Free`. Each one of these functions expects a `FT_Memory` handle as its first parameter. Note, however, that there exist more, similar variants for specific purposes which we skip here for simplicity. By default, this manager uses the ANSI functions `malloc`, `realloc`, and `free`. However, as `ftsystem` is a replaceable part of the base layer, a specific build of the library could provide a different default memory manager.

Font files are always read through `FT_Stream` objects. The definition of `FT_StreamRec` is located in the public header file `ftsystem.h`, which allows client developers to provide their own implementation of streams if they wish so. The function `FT_New_Face` always automatically creates a new stream object from the C pathname given as its second argument. This is achieved by calling the (internal) function `FT_Stream_Open` provided by the `ftsystem` component. As the latter is replaceable, the implementation of streams may vary greatly between platforms. As an example, the default implementation of streams is located in the file `src/base/ftsystem.c` and uses the ANSI functions `fopen`, `fseek`, and `fread`. However, the Unix build of FreeType 2 provides an alternative implementation that uses memory-mapped files, when available on the host platform, resulting in a significant access speed-up.

### Summary

In summary, we learned that FreeType:

- Allows access to font types
- Is composed of modules
- Relies on the low-level API for I/O management
- Performs most memory management through specific routines
- Reads font files through `FT_Stream` objects
- The Unix build provides an implementation that supports memory-mapped files

The documentation highlights several areas that deserve particular attention when working with or testing the library:

- The centralized nature of the memory management system makes it a critical point for reliability testing
- The stream abstraction layer, particularly in Unix builds with memory-mapped files, represents a complex interaction point
- The modular architecture suggests testing should address both module-specific and inter-module interactions

Thankfully, becoming a FreeType expert is not mandatory to write good harnesses. With a solid understanding of its mechanisms, we are now equipped to implement library functions effectively in our harnesses.

## List Interesting Functions

Now that we have a good understanding of what the library does, it's time to make a list of the functions worth trying to fuzz test or important for writing our harness. Starting with the FreeType tutorial page, we collect these functions:

### Tutorial 1

**Library initialization:**
- `FT_Init_FreeType(&library)`

**Loading face:**
- Loading a Font Face from file: `FT_New_Face(library, "/usr/share/fonts/truetype/arial.ttf", 0, &face)`
- Loading a Font Face from memory: `FT_New_Memory_Face(library, buffer, size, 0, &face)`
- From other sources: `FT_Open_Face(library, args, face_index, *aface)`

**Setting current pixel size:**
- Set the char size: `FT_Set_Char_Size(face, 0, 16*64, 300, 300)`
- Set the pixel size: `FT_Set_Pixel_Sizes(face, 0, 16)`

**Loading a glyph image:**
- Convert Unicode character into glyph index: `glyph_index = FT_Get_Char_Index(face, charcode)`
- Loading a glyph from the face: `FT_Load_Glyph(face, glyph_index, load_flags)`
- Convert glyph to bitmap: `FT_Render_Glyph(face->glyph, render_mode)`
- Using other charmap: `FT_Select_Charmap(face, FT_ENCODING_BIG5)`

**Glyph transformations:**
- Set transformation: `FT_Set_Transform(face, &matrix, &delta)`

### Tutorial 2

**Managing glyph:**
- Extracting the glyph image: `FT_Get_Glyph(face->glyph, &glyph)`
- Transforming the glyph image: `FT_Glyph_Transform(glyph, 0, &delta)`
- Copying the glyph image: `FT_Glyph_Copy(glyph, &glyph2)`
- Measuring the glyph image: `FT_Glyph_Get_Cbox(glyph, _bbox_mode_, &bbox)`
- Converting the glyph image: `FT_Glyph_To_Bitmap(&glyph, render_mode, &origin, 1)`

**Global glyph metrics:**
- Load additional metrics via file: `FT_Attach_File`
- Load additional metrics via stream: `FT_Attach_Stream`
- Retrieve kerning information: `FT_Get_Kerning(face, left, right, kerning_mode, &kerning)`

Fortunately, some libraries provide examples, sometimes quite advanced, that can help you identify interesting functions and understand their purpose. In our case, FreeType includes a very useful folder called `ft2demos`, which contains numerous complete usage examples of the library. In this article, we will use these examples to better understand function usage, but you can also use them to compile a list of functions.

Now that we have this list, it gives us a solid starting point. However, it does not cover the entire library. To achieve the deepest possible coverage, we will delve into the library's API documentation. While this part can be time-consuming, the effort is worthwhile for creating a super harness capable of finding bugs.

## API

Another excellent resource for information about library functions is the API documentation. Ideally, all functions should be documented, enabling you to manually craft a thorough and effective harness.

### Core API

#### Face Creation

- **FT_New_Face**: Call `FT_Open_Face` to open a font by its pathname
- **FT_Done_Face**: Discard a given face object, as well as all of its child slots and sizes
- **FT_Reference_Face**: A counter gets initialized to 1 at the time an `FT_Face` structure is created. This function increments the counter. `FT_Done_Face` then only destroys a face if the counter is 1, otherwise it simply decrements the counter
- **FT_New_Memory_Face**: Call `FT_Open_Face` to open a font that has been loaded into memory
- **FT_Face_Properties**: Set or override certain (library or module-wide) properties on a face-by-face basis. Useful for finer-grained control and avoiding locks on shared structures (threads can modify their own faces as they see fit)
- **FT_Open_Face**: Create a face object from a given resource described by `FT_Open_Args`
- **FT_Attach_File**: Call `FT_Attach_Stream` to attach a file
- **FT_Attach_Stream**: 'Attach' data to a face object. Normally, this is used to read additional information for the face object. For example, you can attach an AFM file that comes with a Type 1 font to get the kerning values and other metrics

#### Font Testing Macros

- **FT_HAS_HORIZONTAL**: check for horizontal metrics
- **FT_HAS_VERTICAL**: check for vertical metrics
- **FT_HAS_KERNING**: check if a face contains kerning data that can be accessed by `FT_Get_Kerning`
- **FT_HAS_FIXED_SIZES**: check if a face contains embedded bitmaps
- **FT_HAS_GLYPH_NAMES**: check if a face contains some glyph names
- **FT_HAS_COLOR**: check if a face contains table for color glyphs
- **FT_HAS_MULTIPLE_MASTERS**: check if a face contains multiple masters
- **FT_HAS_SVG**: check if a face contains an SVG OpenType table
- **FT_HAS_SBIX**: check if a face contains an sbix OpenType table and outline glyphs
- **FT_HAS_SBIX_OVERLAY**: check if a face contains an sbix OpenType table with bit 1 in its flags field set
- **FT_IS_SFNT**: check if a face contains a font whose format is based on SFNT storage scheme
- **FT_IS_SCALABLE**: check if a face contains a scalable font face
- **FT_IS_FIXED_WITH**: check if a face contains a font face that contains fixed-width
- **FT_IS_CID_KEYED**: check if a face contains a CID-keyed font
- **FT_IS_TRICKY**: check if a face represent a tricky font
- **FT_IS_NAMED_INSTANCE**: check if a face is a named instance of a GX or OpenType variation font
- **FT_IS_VARIATION**: check if a face has been altered by `FT_Set_MM_Design_Coordinates`, `FT_Set_Var_Design_Coordinates`, `FT_Set_Var_Blend_Coordinates`, or `FT_Set_MM_WeightVector`

#### Sizing and Scaling

- **FT_Set_Char_Size**: Call `FT_Request_Size` to request the nominal size
- **FT_Set_Pixel_Sizes**: Call `FT_Request_Size` to request nominal size (in pixels)
- **FT_Request_Size**: Resize the scale of the active `FT_Size` object in face
- **FT_Select_Size**: Select a bitmap strike, sets the scaling factors of the active `FT_Size` object in the face
- **FT_Set_Transform**: Set the transform that is applied to the glyph images when they are loaded into a glyph slot through `FT_Load_Glyph`
- **FT_Get_Transform**: returns the transformation that is applied to a glyph images when they are loaded in to a glyph slot through `FT_Load_Glyph`

#### Glyph Retrieval

- **FT_Load_Glyph**: Load a glyph into the glyph slot of a face object
- **FT_Render_Glyph**: Convert a given glyph image to a bitmap
- **FT_Get_Kerning**: Return the kerning vector between two glyphs of the same face
- **FT_Get_Track_Kerning**: Return the track kerning for a given face object at a given size

#### Character Mapping

- **FT_Select_Charmap**: Select a given charmap by its encoding
- **FT_Set_Charmap**: Select a given charmap for character code to glyph index mapping
- **FT_Get_Charmap_Index**: Retrieve index of given charmap
- **FT_Get_Char_Index**: Return the glyph index of a given character code
- **FT_Get_First_Char**: Return the first character code in the current charmap
- **FT_Get_Next_Char**: Return the next character code in the current charmap
- **FT_Load_Char**: Load a glyph into the glyph slot of a face object accessed by its char code

#### Information Retrieval

- **FT_Get_Name_Index**: Return the glyph index of a given glyph name
- **FT_Get_Glyph_Name**: Retrieve the ASCII name of a given glyph face
- **FT_Get_Postscript_Name**: Retrieve the ASCII postscript name of a given face
- **FT_Get_FSType_Flags**: Return the fsType flags for a font
- **FT_Get_SubGlyph_Info**: Retrieve a description of a given subglyph

### Extended API

#### Unicode Variation Sequences

- **FT_Face_GetCharVariantIndex**: Return the glyph index of a given character code as modified by the variation selector
- **FT_Face_GetCharVariantIsDefault**: Check whether this variation of this Unicode character is the one to be found in the charmap
- **FT_Face_GetVariantSelectors**: Return a zero-terminated list of Unicode variation selectors found in the font
- **FT_Face_GetVariantsOfChar**: Return a zero-terminated Unicode variation selectors found for the specified character code
- **FT_Face_GetCharsOfVariant**: Return a zero-terminated list of Unicode characters codes found for the specified variation selector

#### Glyph Color Management

- **FT_Palette_Data_Get**: Retrieve the face color palette data
- **FT_Palette_Select**: This function has two purposes: It activates a palette for rendering / It retrieves all (unmodified) color entries of this palette. The function returns a read/write array which means that a calling application can modify the palette entries on demand
- **FT_Palette_Set_Foreground_Color**: COLR uses palette index 0xFFF to indicate a text foreground color. This function sets this value

#### Glyph Layer Management

- **FT_Get_Color_Glyph_Layer**: This is an interface for the 'COLR' v1 table in OpenType fonts to iteratively retrieve colored glyph layers associated with the current glyph slot
- **FT_Get_Color_Glyph_Paint**: Starting point and interface to color gradient information in a 'COLR' v1 table in OpenType fonts to retrieve the paints tables for the directed acyclic graph
- **FT_Get_Color_Glyph_ClipBox**: Search for a 'COLR' v1 clip box for the specified base_glyph and fill the clip_box parameter with the information
- **FT_Get_Paint_Layer**: Access the layers of PaintColrLayers table
- **FT_Get_Colorline_Stops**: This is an interface to color gradient information in a 'COLR' v1 table, retrieving the gradient and solid fill information
- **FT_Get_Paint**: Access the details of a paint using an `FT_OpaquePaint` object

#### Glyph Management

- **FT_New_Glyph**: Create a new empty glyph image
- **FT_Get_Glyph**: Extract a glyph image from a slot
- **FT_Glyph_Copy**: Copy a glyph image
- **FT_Glyph_Transform**: Transform a glyph image if its format is scalable
- **FT_Glyph_Get_CBox**: Return a glyph control box
- **FT_Glyph_To_Bitmap**: Convert a given glyph object to a bitmap glyph object
- **FT_Done_Glyph**: destroy a given glyph

The extensive API surface for font manipulation presents multiple vectors for both bug discovery and potential security vulnerabilities. Functions like `FT_Face_Properties` and `FT_Attach_Stream` allow for dynamic modification of face objects and attachment of external data, which could expose memory corruption bugs or buffer overflow vulnerabilities if input validation is insufficient. The transformation functions (`FT_Set_Transform`, `FT_Glyph_Transform`) introduce complex mathematical operations that might reveal numerical precision issues or edge cases in coordinate calculations. Color management functions (`FT_Palette_Select`, `FT_Get_Color_Glyph_Paint`) add an additional layer of complexity by handling color tables and gradients, potentially exposing parsing bugs or memory issues when processing malformed color data. The glyph management functions, particularly `FT_Glyph_To_Bitmap` and `FT_Get_Color_Glyph_Layer`, involve format conversion and layer processing that could uncover issues with memory management or reveal bugs in the rendering pipeline. Testing these functions thoroughly is crucial as they often interact with complex font data structures and perform memory operations that could lead to crashes or security vulnerabilities if not properly handled.

## Write a Harness

### Harness Tutorial 1

Our first harness will be using functions collected from tutorial 1:

- `FT_Init_Freetype`
- `FT_New_Face`
- `FT_Set_Char_Size`
- `FT_Set_Pixel_Sizes`
- `FT_Get_Char_Index`
- `FT_Load_Glyph`
- `FT_Render_Glyph`
- `FT_Set_Transform`

```c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ft2build.h>
#include <math.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H

#define NUM_ENCODINGS (sizeof(supported_encodings) / sizeof(supported_encodings[0]))
#define MAX_GLYPHS 256
#define BUFFER_SIZE 1024

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 10) return 0;  // Reject very small inputs

    FT_Library library;
    FT_Face face;
    FT_Error error;
    FT_UInt glyph_index;
    FT_Vector kerning, delta;
    FT_Matrix matrix;
    char buffer[BUFFER_SIZE];

    // Supported encodings array
    FT_Encoding supported_encodings[] = {
        FT_ENCODING_NONE,
        FT_ENCODING_MS_SYMBOL,
        FT_ENCODING_UNICODE,
        FT_ENCODING_SJIS,
        FT_ENCODING_PRC,
        FT_ENCODING_BIG5,
        FT_ENCODING_WANSUNG,
        FT_ENCODING_JOHAB,
        FT_ENCODING_ADOBE_STANDARD,
        FT_ENCODING_ADOBE_EXPERT,
        FT_ENCODING_ADOBE_CUSTOM,
        FT_ENCODING_ADOBE_LATIN_1,
        FT_ENCODING_OLD_LATIN_2,
        FT_ENCODING_APPLE_ROMAN
    };

    // Initialize FreeType library
    error = FT_Init_FreeType(&library);
    if (error) return 0;

    // Create new face from memory
    error = FT_New_Memory_Face(library, data, size, 0, &face);
    if (error) {
        FT_Done_FreeType(library);
        return 0;
    }

    // Initialize transformation matrix
    double angle = (data[0] % 360) * 3.14159 / 180.0;  // Use first byte for rotation
    matrix.xx = (FT_Fixed)(cos(angle) * 0x10000L);
    matrix.xy = (FT_Fixed)(-sin(angle) * 0x10000L);
    matrix.yx = (FT_Fixed)(sin(angle) * 0x10000L);
    matrix.yy = (FT_Fixed)(cos(angle) * 0x10000L);

    // Initialize delta based on input data
    delta.x = ((int16_t)(data[1] << 8 | data[2])) * 64;
    delta.y = ((int16_t)(data[3] << 8 | data[4])) * 64;

    // Test face properties
    if (FT_HAS_HORIZONTAL(face)) {
        // Get font metrics
        FT_Size_RequestRec req;
        req.type = FT_SIZE_REQUEST_TYPE_NOMINAL;
        req.width = 0;
        req.height = (data[5] % 32 + 8) * 64;  // 8-40 pt size
        req.horiResolution = 96;
        req.vertResolution = 96;
        FT_Request_Size(face, &req);
    }

    // Select and test different character maps
    if (face->num_charmaps > 0) {
        FT_Select_Charmap(face, supported_encodings[data[6] % NUM_ENCODINGS]);

        // Get all available characters
        FT_ULong charcode;
        FT_UInt gindex;
        charcode = FT_Get_First_Char(face, &gindex);

        // Store up to MAX_GLYPHS characters for testing
        FT_ULong charcodes[MAX_GLYPHS];
        FT_UInt gindices[MAX_GLYPHS];
        int num_chars = 0;

        while (gindex != 0 && num_chars < MAX_GLYPHS) {
            charcodes[num_chars] = charcode;
            gindices[num_chars] = gindex;
            num_chars++;
            charcode = FT_Get_Next_Char(face, charcode, &gindex);
        }

        // Test kerning if available
        if (FT_HAS_KERNING(face) && num_chars > 1) {
            for (int i = 0; i < num_chars - 1 && i < 10; i++) {  // Limit iterations
                FT_Vector kern;
                FT_Get_Kerning(face, gindices[i], gindices[i+1], 
                              FT_KERNING_DEFAULT, &kern);

                // Test track kerning
                FT_Fixed track_kern;
                FT_Get_Track_Kerning(face, face->size->metrics.x_ppem * 64,
                                   -2, &track_kern);
            }
        }

        // Test glyph loading and rendering
        for (int i = 0; i < num_chars && i < 10; i++) {  // Limit iterations
            error = FT_Load_Char(face, charcodes[i], FT_LOAD_DEFAULT);
            if (!error) {
                FT_Render_Glyph(face->glyph, FT_RENDER_MODE_NORMAL);

                // If glyph names are available, test name functions
                if (FT_HAS_GLYPH_NAMES(face)) {
                    FT_Get_Glyph_Name(face, gindices[i], buffer, BUFFER_SIZE);
                    FT_Get_Name_Index(face, (FT_String*)buffer);
                }

                // Test subglyph information if available
                if (face->glyph->format == FT_GLYPH_FORMAT_COMPOSITE) {
                    FT_UInt index;
                    FT_Int p1, p2;
                    FT_UInt flags;
                    FT_Matrix submatrix;

                    for (int j = 0; j < face->glyph->num_subglyphs; j++) {
                        FT_Get_SubGlyph_Info(face->glyph, j, &index, &flags,
                                           &p1, &p2, &submatrix);
                    }
                }
            }
        }
    }

    // Test other face properties
    if (FT_HAS_MULTIPLE_MASTERS(face)) {
        // Could add Multiple Master specific tests here
    }

    if (FT_HAS_COLOR(face)) {
        // Could add color-specific tests here
    }

    // Get PostScript name and FSType flags
    FT_Get_Postscript_Name(face);
    FT_Get_FSType_Flags(face);

    // Cleanup
    FT_Done_Face(face);
    FT_Done_FreeType(library);
    return 0;
}
```

This harness, despite being trivial, is a perfectly good example of what you can code to start fuzzing a library. It contains interesting functions for AFL to explore that could contain potential bugs.

### Harness Tutorial 2

Our second harness will be using functions collected from tutorial 2:

- `FT_Init_Freetype`
- `FT_New_Face`
- `FT_Get_Char_Index`
- `FT_Get_Glyph`
- `FT_Glyph_Copy`
- `FT_Glyph_Transform`
- `FT_Glyph_Get_CBox`
- `FT_Get_Kerning`

The harness code follows the same structure as Tutorial 1, implementing the tutorial 2 functions.

## Improving Harness

We can improve drastically the speed of execution of our harness by using AFL++ persistent mode to pass input from memory instead of using File I/O.

### LLVMTestOneInput

The `LLVMFuzzerTestOneInput` function signature is already optimized for persistent mode fuzzing as it accepts data directly from memory.

### AFL Persistent Mode

This allows our harness to go from 5000 exec/sec to 40000 exec/sec!

### Harness API

There are multiple ways to write harnesses. You can choose to write one BIG harness that uses a lot (or every) function, or you can group some functions together. We are going to do both:

- A relatively small harness per API sub-topic
- A medium harness per API called API harness

#### API Sub-topic Harnesses

**Font Testing Macros harness**

This harness focuses specifically on testing all the `FT_HAS_*` and `FT_IS_*` macros to verify font capabilities.

**Sizing and Scaling**

This harness concentrates on the sizing and scaling functions like `FT_Set_Char_Size`, `FT_Set_Pixel_Sizes`, `FT_Request_Size`, and transformation functions.

**Glyph Retrieval**

This harness exercises glyph loading, rendering, and retrieval functions.

## Tips and Tricks

When diving into fuzzing projects, consider these strategies to enhance your approach:

### Leveraging Existing Work

- **Search for Existing Harnesses**: Google previous researchers' work to find potential harnesses that you can adapt or learn from
- **Explore Project Test Suites**: Many projects implement their own fuzzing tests. Reviewing these can reveal what areas are already covered and where potential gaps lie, giving you a strategic advantage
- **Check OSS-Fuzz Coverage**: Examine which parts of the library or functions are covered by OSS-Fuzz. Identifying overlooked areas can lead to interesting discoveries

### General Tips

- **Build a Robust Corpus**: A diverse and well-curated input corpus is critical for effective fuzzing
- **Optimize Compilation**:
  - Compile a fraction of your builds (e.g., 1/15) with AddressSanitizer (ASan) for better bug detection
  - Use optimization flags like `-O3` for improved coverage during fuzzing
- **Utilize Advanced Tools**: Consider using Redqueen for input-to-state correspondence and deeper insights
- **Optimize Your System**: Follow the AFL++ performance tips to ensure your fuzzing environment is efficient and performant
- **Seek Inspiration**: Learn from other resources and articles:
  - [Fuzzing Techniques and Harness Writing](https://example.com)
  - [Awesome LibFuzzer Harness Collection](https://example.com)

You can find more harnesses I made for this article [here](https://example.com)

## Going Further

Many researchers are tackling the challenges of harness creation by proposing various approaches to automate this task. You can find inspiration in the following papers:

- Automated Fuzzing Harness Generation for Library APIs and Binary Protocol Parsers
- FuzzGen: Automatic Fuzzer Generation
- Automated Fuzzing Harness Generation for Library APIs and Binary Protocol Parsers

## Conclusion

Creating a harness isn’t just about running tools, it’s about understanding the nuances of your target, anticipating edge cases, and iterating on what you learn. A good fuzzing harness isn’t perfect on the first attempt, but a carefully constructed one evolves into an indispensable tool for finding bugs and understanding the target's behavior under stress. A good harness is one that offers the highest coverage with a good execution speed. It should cover the largest part of the library codebase you want to test, whether through multiple small harnesses or a single large one. An efficient harness is also strategic—for example, you could leave heavy computational features outside of your general harness to focus on usual functions, allowing you to cover more edge cases and fuzz the heavy ones separately. These strategies can only come from the researcher’s experience with their target.

By following the principles and strategies laid out here, you’re not just building a harness; you’re equipping yourself to systematically tear into assumptions, test boundaries, and uncover vulnerabilities that others might miss. Whether your target is a well-known library or something more obscure, this approach gives you the foundation to fuzz effectively and meaningfully. Harnessing isn’t glamorous—it’s technical, iterative, and occasionally frustrating. But when the crash reports start rolling in, you’ll know it was worth the effort.