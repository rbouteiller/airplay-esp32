////////////////////////////////////////////////////////////////////////////
//                         **** RESAMPLER ****                            //
//                     Sinc-based Audio Resampling                        //
//                Copyright (c) 2006 - 2023 David Bryant.                 //
//                          All Rights Reserved.                          //
//      Distributed under the BSD Software License (see license.txt)      //
////////////////////////////////////////////////////////////////////////////

// resampler.c

#include "resampler.h"

#ifdef ENABLE_EXTRAPOLATION
#include "extrapolator.h"
#endif

static void init_filter(Resample *cxt, artsample_t *filter, double fraction);
static double subsample_no_interpolate_precise(Resample *cxt,
                                               artsample_t *source,
                                               double offset);
static double subsample_interpolate_precise(Resample *cxt, artsample_t *source,
                                            double offset);
static double subsample_no_interpolate(Resample *cxt, artsample_t *source,
                                       double offset);
static double subsample_interpolate(Resample *cxt, artsample_t *source,
                                    double offset);
static unsigned long gcd(unsigned long a, unsigned long b);

// There are now two functions to initialize a resampler context. The legacy
// version is for arbitrary resampling operations with no fixed ratio (i.e.,
// ASRCs), and its API is unchanged from previous versions of the resampler. The
// resampler initially targeted this use case.
//
// A new version of the initialization function, resamplerFixedRatioInit(), is
// for fixed-ratio sample rate conversions (i.e., conversions from one specific
// sample rate to another) with no fractional phase shift. This version can
// provide significantly improved performance and accuracy for such conversions.
// See the new function's description below.

////////////////////////////////////////////////////////////////////////////////////////////////////

// Initialize a resampler context with the specified characteristics. The
// returned context pointer is used for all subsequent calls to the resampler
// (and should not be dereferenced). A NULL return indicates an error. For the
// flags parameter, note that SUBSAMPLE_INTERPOLATE and BLACKMAN_HARRIS are
// recommended for most applications. This function assumes that the "ratio"
// parameter will be appropriately specified for every call to the resampler.
// The parameters are:
//
// numChannels:     the number of audio channels present
//
// numTaps:         the number of taps for each sinc interpolation filter
//                    - must be a multiple of 4, from 4 - 1024 taps
//                    - affects quality by controlling cutoff sharpness of
//                    filters
//                    - linearly affects memory usage and CPU load of resampling
//
// numFilters:      the number of sinc filters generated
//                    - must be 1 - 1024
//                    - affects quality of interpolated filtering
//                    - linearly affects memory usage of resampler
//
// lowpassRatio:    enable lowpass by specifying the ratio relative to the
// Nyquist frequency of
//                   the *input* samples (must be > 0.0 and < 1.0); required for
//                   quality downsampling (except in special cases), but is
//                   optional otherwise ex: lowpassRatio = lowpass freq in Hz /
//                   (source rate in Hz / 2.0)
//
// flags:           mask for optional feature configuration:
//
//   SUBSAMPLE_INTERPOLATE:     interpolate values from adjacent filters
//                                - generally recommended except in special
//                                situations
//                                - approximately doubles the CPU load
//
//   BLACKMAN_HARRIS:           use 4-term Blackman Harris window function
//                                - generally recommended except in special
//                                situations
//                                - if not specified, the default window is Hann
//                                (raised cosine)
//                                  which has steeper cutoff but poorer stopband
//                                  rejection
//
//   RESAMPLE_MULTITHREADED:    use multiple threads for processing multiple
//   channels in parallel
//                                - might be slower depending on CPU,
//                                optimization, caching, etc.
//                                - optional (define ENABLE_THREADS)
//
//
//   EXTRAPOLATE_ENDPOINTS      enable sample extrapolation at the beginning and
//   end of conversion
//                                - to use this properly, the resampleAdvance()
//                                function must be
//                                  called BEFORE sending any data to the
//                                  resampler to delay the initial conversion
//                                  (otherwise samples will be generated
//                                  immediately when there aren't enough samples
//                                  to extrapolate)
//                                - also, the new "flush" functionality must be
//                                used instead of
//                                  just sending zeros to the resampler to
//                                  perform a final flush (although this should
//                                  be obvious)
//                                - optional (define ENABLE_EXTRAPOLATION)
//
//   EXTEND_CONVOLUTION_MATH    use precise math in convolution (doubles, not
//   floats)
//                                - this can improve resampling quality, but
//                                just a few dB at best
//                                - can result in significant performance hit on
//                                some platforms
//                                - might be worth it, but generally not
//                                recommended
//                                - non-operational when the 64-bit path
//                                selected
// Notes:
//
// 1. The same resampling instance can be used for upsampling, downsampling, or
// simple (near-unity)
//    resampling (e.g., for asynchronous sample rate conversion, phase shifting,
//    or filtering). The behavior is controlled by the "ratio" parameter during
//    the actual resample processing call. To prevent aliasing, it's important
//    to specify a lowpassRatio if the resampler will be used for any
//    significant degree of downsampling (ratio < 1.0), but the lowpass can also
//    be used independently without any rate conversion (or even when
//    upsampling).
//
// 2. When the context is initialized (or reset) the sample histories are filled
// with silence such
//    that the resampler is ready to generate output immediately. However, this
//    also means that there is an implicit signal delay equal to half the tap
//    length of the sinc filters in samples. If zero delay is desired then that
//    many samples can be ignored, or the resampleAdvancePosition() function can
//    be used to bypass them. Also, at the end of processing an equal length of
//    silence must be appended to the input audio to align the output with the
//    actual input.
//
// 3. Both the number of interpolation filters and the number of taps per filter
// directly control
//    the fidelity of the resampling. The filter length has an approximately
//    linear affect on the the CPU load consumed by the resampler, and also on
//    the memory requirement (both for the filters themselves and also for the
//    sample history storage). On the other hand, the number of filters
//    allocated primarily affects just the memory footprint (it has little
//    affect on CPU load and so can be large on systems with lots of RAM).
//
//  4. For a fixed-ratio conversion (i.e., conversions from one specific sample
//  rate to another) with
//     no fractional phase shift, see resampleFixedRatioInit() below.

Resample *resampleInit(int numChannels, int numTaps, int numFilters,
                       double lowpassRatio, int flags) {
  Resample *cxt;
  int i;

  if (lowpassRatio > 0.0 && lowpassRatio < 1.0) {
    flags |= INCLUDE_LOWPASS;
  } else {
    flags &= ~INCLUDE_LOWPASS;
    lowpassRatio = 1.0;
  }

  if ((numTaps & 3) || numTaps <= 0 || numTaps > 1024) {
    fprintf(stderr, "must 4-1024 filter taps, and a multiple of 4!\n");
    return NULL;
  }

  if (numFilters < 1 || numFilters > 1024) {
    fprintf(stderr, "must be 1-1024 filters!\n");
    return NULL;
  }

  cxt = calloc(1, sizeof(Resample));
  if (!cxt) {
    return NULL;
  }

  cxt->lowpassRatio = lowpassRatio;
  cxt->numChannels = numChannels;
  cxt->numSamples = numTaps * 16;
  cxt->numFilters = numFilters;
  cxt->numTaps = numTaps;
  cxt->flags = flags;

  // note that we actually have one more than the specified number of filters

  cxt->filters =
      (artsample_t **)calloc(cxt->numFilters + 1, sizeof(artsample_t *));
  cxt->tempFilter = malloc(numTaps * sizeof(double));

  for (i = 0; i <= cxt->numFilters; ++i) {
    int j;

    cxt->filters[i] = calloc(cxt->numTaps, sizeof(artsample_t));

    if (i < cxt->numFilters) {
      init_filter(cxt, cxt->filters[i], (double)i / cxt->numFilters);
    } else {
      // the last filter is essentially identical to the first (just offset one
      // tap)
      for (j = 0; j < cxt->numTaps; ++j) {
        cxt->filters[cxt->numFilters][(j + 1) % cxt->numTaps] =
            cxt->filters[0][j];
      }
    }
  }

  // The first and last filters should actually have just an odd number of taps,
  // but Blackman-Harris doesn't go all the way to zero, so clear the outliers
  // here. This almost eliminates the tiny discrepancies caused by different
  // processing chunk sizes (those remaining come from math errors and
  // rounding).

  cxt->filters[0][cxt->numTaps - 1] = (artsample_t)0.0;
  cxt->filters[cxt->numFilters][0] = (artsample_t)0.0;

  free(cxt->tempFilter);
  cxt->tempFilter = NULL;
  cxt->buffers = (artsample_t **)calloc(numChannels, sizeof(artsample_t *));

  for (i = 0; i < numChannels; ++i) {
    cxt->buffers[i] = calloc(cxt->numSamples, sizeof(artsample_t));
  }

  cxt->outputOffset = numTaps / 2.0;
  cxt->inputIndex = numTaps;

#ifdef ENABLE_EXTRAPOLATION
  if (cxt->flags & EXTRAPOLATE_ENDPOINTS) {
    cxt->flags |= EXTRAPOLATE_PREFILL;
  }
#endif

#ifdef ENABLE_THREADS
  if (numChannels > 1 && (flags & RESAMPLE_MULTITHREADED)) {
    cxt->workers = workersInit(numChannels);
  }
#endif

  // extended math only makes sense if we have a 32-bit path

  if (sizeof(artsample_t) == 4 && (cxt->flags & EXTEND_CONVOLUTION_MATH)) {
    cxt->subsample = (cxt->flags & SUBSAMPLE_INTERPOLATE)
                         ? subsample_interpolate_precise
                         : subsample_no_interpolate_precise;
  } else {
    cxt->subsample = (cxt->flags & SUBSAMPLE_INTERPOLATE)
                         ? subsample_interpolate
                         : subsample_no_interpolate;
  }

  return cxt;
}

// Initialize a resampler context with the specified characteristics. The
// returned context pointer is used for all subsequent calls to the resampler
// (and should not be dereferenced). A NULL return indicates an error. For the
// flags parameter, note that SUBSAMPLE_INTERPOLATE, BLACKMAN_HARRIS, and
// INCLUDE_LOWPASS are all recommended for most applications.
//
// This function will determine whether the specified fixed-ratio conversion
// operation is possible with a reduced number of filters that can be used
// directly without interpolation (i.e., every calculation exactly aligns to a
// single filter). If this is possible then several advantages result. First,
// fewer filters are required which reduces the memory footprint. Also, the
// performance is approximately doubled due to the elimination of the
// interpolation step. And finally, the numerical accuracy of the resampling is
// improved, also due to the lack of interpolation inaccuracies. Note that
// subsample phase shifts are not allowed in this mode, so if these are required
// set the NO_FILTER_REDUCTION bit in the flags to prevent this optimization.
//
// If the number of filters cannot be reduced because the sample rates are not
// sufficiently related for the max number of filters specified, then that
// specified maximum filter count will be used with the specfied interpolation
// mode (recommended to be ON). If the number filters is reduced, then the
// supplied interpolation mode flag is ignored.
//
// When using this version there is also the ability of the resampler to choose
// an optimum lowpass cutoff frequency for downsampling operations only based on
// the sampling rates and the number of filter taps. Simply set the
// INCLUDE_LOWPASS bit in the flags parameter and set the lowpassFreq parameter
// to zero. This is generally recommended because it does not introduce a
// lowpass for upsampling.
//
// numChannels:     the number of audio channels present
//
// numTaps:         the number of taps for each sinc interpolation filter
//                    - must be a multiple of 4, from 4 - 1024 taps
//                    - affects quality by controlling cutoff sharpness of
//                    filters
//                    - linearly affects memory usage and CPU load of resampling
//
// maxFilters:      the maximum number of sinc filters allowed
//                    - must be 1 - 1024, will be reduced if possible
//                    - affects quality of interpolated filtering
//                    - linearly affects memory usage of resampler
//
// sourceRate:      the fixed source and destination sample rates
// destinRate:        - the "ratio" parameter to other resampling functions is
// ignored
//
// lowpassFreq:     enable lowpass by specifying a lowpass frequency here
//                    - to have the library determine an appropriate lowpass
//                    frequency based
//                      on the sample rates and filter length, leave this
//                      parameter zero and set the INCLUDE_LOWPASS flag bit
//                      below
//
// flags:           mask for optional feature configuration:
//
//   SUBSAMPLE_INTERPOLATE:     interpolate values from adjacent filters
//                                - recommended in case the reduced filter
//                                determination fails
//                                - will be ignored if a reduced filter count is
//                                selected
//                                - approximately doubles the CPU load (if used)
//
//   NO_FILTER_REDUCTION:       don't allow the automatic reduction of filter
//   count optimization
//                                - this prevents the resampler from attempting
//                                to reduce the
//                                  number of filters, which includes disabling
//                                  interpolation
//                                - only necessary if subsample phase-shifts are
//                                required, which
//                                  is not a normal use case for fixed-ratio
//                                  resampling
//
//   BLACKMAN_HARRIS:           use 4-term Blackman Harris window function
//                                - generally recommended except in special
//                                situations
//                                - if not specified, the default window is Hann
//                                (raised cosine)
//                                  which has steeper cutoff but poorer stopband
//                                  rejection
//
//   RESAMPLE_MULTITHREADED:    use multiple threads for processing multiple
//   channels in parallel
//                                - might be slower depending on CPU,
//                                optimization, caching, etc.
//                                - optional (define ENABLE_THREADS)
//
//   INCLUDE_LOWPASS:           enable automatic calculation of appropriate
//   lowpass frequency
//                                - also set the lowpassFreq parameter (above)
//                                to zero
//                                - calculation is based on sample rates and
//                                filter length
//                                - no lowpass is used for upsampling or
//                                near-unity resampling,
//                                  but can always be enabled by setting the
//                                  lowpassFreq directly
//
//   EXTRAPOLATE_ENDPOINTS      enable sample extrapolation at the beginning and
//   end of conversion
//                                - to use this properly, the resampleAdvance()
//                                function must be
//                                  called BEFORE sending any data to the
//                                  resampler to delay the initial conversion
//                                  (otherwise samples will be generated
//                                  immediately when there aren't enough samples
//                                  to extrapolate)
//                                - also, the new "flush" functionality must be
//                                used instead of
//                                  just sending zeros to the resampler to
//                                  perform a final flush (although this should
//                                  be obvious)
//                                - optional (define ENABLE_EXTRAPOLATION)
//
//   EXTEND_CONVOLUTION_MATH    use precise math in convolution (doubles, not
//   floats)
//                                - this can improve resampling quality, but
//                                just a few dB at best
//                                - can result in significant performance hit on
//                                some platforms
//                                - might be worth it, but generally not
//                                recommended
//                                - non-operational when the 64-bit path
//                                selected
// Notes:
//
// 1. The resampling instance created by this call can only be used to perform
// the specified
//    conversion as the "ratio" parameter in the processing functions is
//    ignored. Also subsample phase advances are not allowed.
//
// 2. When the context is initialized (or reset) the sample histories are filled
// with silence such
//    that the resampler is ready to generate output immediately. However, this
//    also means that there is an implicit signal delay equal to half the tap
//    length of the sinc filters in samples. If zero delay is desired then that
//    many samples can be ignored, or the resampleAdvancePosition() function can
//    be used to bypass them. Also, at the end of processing an equal length of
//    silence must be appended to the input audio to align the output with the
//    actual input.
//
// 3. The number of taps per filter directly control the fidelity of the
// resampling. The filter length
//    has an approximately linear affect on the the CPU load consumed by the
//    resampler, and also on the memory requirement (both for the filters
//    themselves and also for the sample history storage). It is assumed that
//    this version of the resampler instance has exactly the optimum number of
//    filters to eliminate the need for interpolation and provide the highest
//    possible accuracy, but otherwise the maximum number of filters specified
//    will be used.

Resample *resampleFixedRatioInit(int numChannels, int numTaps, int maxFilters,
                                 double sourceRate, double destinRate,
                                 int lowpassFreq, int flags) {
  double lowpassRatio = lowpassFreq / (destinRate / 2.0);
  double resampleRatio = destinRate / sourceRate;
  Resample *cxt;

  if (lowpassFreq > destinRate / 2.0) {
    fprintf(stderr,
            "lowpass frequency must be lower than destination Nyquist!\n");
    return NULL;
  }

  // if we can use the exact number of filters for interpolation-free resampling
  // without exceeding the specified limit, do it

  if (sourceRate == floor(sourceRate) && destinRate == floor(destinRate) &&
      !(flags & NO_FILTER_REDUCTION)) {
    unsigned long factor =
        (unsigned long)destinRate /
        gcd((unsigned long)sourceRate, (unsigned long)destinRate);

    if (factor <= maxFilters) {
      flags &= ~SUBSAMPLE_INTERPOLATE;
      maxFilters = (int)factor;

      // if the number of filters is not a power of two, snap to the nearest
      // filter after each buffer

      if (maxFilters & (maxFilters - 1)) {
        flags |= RESAMPLER_SNAP_OFFSET;
      }
    }
  }

  // this is where we calculate an optimized lowpass ratio for the specified
  // rates and filter length current target is around 98 dB attenuation at the
  // Nyquist frequency, assuming a long enough filter

  if (!lowpassFreq && (flags & INCLUDE_LOWPASS) && destinRate < sourceRate) {
    lowpassRatio = 1.0 - (7.5 / numTaps / resampleRatio);

    if (lowpassRatio < 0.8) {
      lowpassRatio = 0.8;
    }

    if (lowpassRatio < resampleRatio) {
      lowpassRatio = resampleRatio;
    }
  }

  cxt =
      resampleInit(numChannels, numTaps, maxFilters,
                   lowpassRatio * resampleRatio, flags | RESAMPLE_FIXED_RATIO);

  if (cxt) {
    cxt->fixedRatio = destinRate / sourceRate;
  }

  return cxt;
}

// Here are several functions to query the configuration of the resampler. These
// were not previously required because the configuration was fully specfied by
// the initialization call, but with the new fixed-ratio initialization some
// configuration is indeterminate.

// Note that lowpass ratio is relative to the Nyquist frequency of the *source*
// sample rate with 1.0 indicating no lowpass configured.

double resampleGetLowpassRatio(Resample *cxt) {
  return cxt->lowpassRatio;
}

int resampleGetNumFilters(Resample *cxt) {
  return cxt->numFilters;
}

int resampleInterpolationUsed(Resample *cxt) {
  return cxt->flags & SUBSAMPLE_INTERPOLATE;
}

// Reset a resampler context to its initialized state. Specifically, any history
// is discarded and this should be used when an audio "flush" or other
// discontinuity occurs.

void resampleReset(Resample *cxt) {
  int i;

  for (i = 0; i < cxt->numChannels; ++i) {
    memset(cxt->buffers[i], 0, cxt->numSamples * sizeof(artsample_t));
  }

  cxt->outputOffset = cxt->numTaps / 2.0;
  cxt->inputIndex = cxt->numTaps;

  if (cxt->flags & EXTRAPOLATE_ENDPOINTS) {
    cxt->flags |= EXTRAPOLATE_PREFILL;
  }

  cxt->flags &=
      ~RESAMPLER_FLUSHED; // resampler can now be used again after flush
}

// Run the resampler context at the specified output ratio and return both the
// number of input samples consumed and output samples generated (in the
// ResampleResult structure). Over time the average number of output samples
// will be equal to the number of input samples multiplied by the given ratio,
// but of course in a single call only an integer number of samples can be
// generated. The numInputFrames parameter indicates the number of samples
// available at "input" and the numOutputFrames indicates the number of samples
// at "output" that can be written. The resampling proceeds until EITHER the
// input is exhausted or space at the output is exhausted (there is no other
// limit).
//
// This is the "non-interleaved" version of the resampler where the audio sample
// buffers for different channels are passed in as an array of float pointers.
// There is also an "interleaved" version (see below).
//
// If this resampler was created with the resampleFixedRatioInit() function,
// then the "ratio" parameter is ignored and the originally specified conversion
// is performed.
//
// To perform a "flush" operation on the resampler, set the numInputFrames to -1
// (the input pointer can be NULL in this case). This flush is required to align
// the output of the resampler, which is delayed by half the sinc filter width,
// with the input. Previously, this flush alignment was forced by feeding the
// appropriate number of zeros into the resampler, but now this can be
// accomplished explicitly, and more cleanly, this way. Also, if sample
// extrapolation has been selected in the init call (with the
// EXTRAPOLATE_ENDPOINTS flag), that is also performed during the flush.

#ifdef ENABLE_THREADS
static int resampleProcessChannelJob(void *ptr, void *sync_not_used);
#endif

#ifdef ENABLE_EXTRAPOLATION
static void prefillAllChannels(Resample *cxt),
    postfillAllChannels(Resample *cxt);
#else
static void postfillAllChannels(Resample *cxt);
#endif

ResampleResult resampleProcess(Resample *cxt, const artsample_t *const *input,
                               int numInputFrames, artsample_t *const *output,
                               int numOutputFrames, double ratio) {
  if (cxt->flags & RESAMPLE_FIXED_RATIO) { // override any supplied ratio if
                                           // doing fixed ratio resampling
    ratio = cxt->fixedRatio;
  }

  if (cxt->flags &
      RESAMPLER_FLUSHED) { // ignore new input after flush but before reset
    numInputFrames = 0;
  }

#ifdef ENABLE_THREADS
  if (cxt->workers) {
    Resample *worker_contexts = calloc(cxt->numChannels, sizeof(Resample));
    ResampleResult res = {0, 0};
    int ch;

    for (ch = 0; ch < cxt->numChannels; ++ch) {
      Resample *wcxt = worker_contexts + ch;

      *wcxt = *cxt;
      if (input) {
        wcxt->input = input[ch] - 1;
      }
      wcxt->numInputFrames = numInputFrames;
      wcxt->output = output[ch] - 1;
      wcxt->numOutputFrames = numOutputFrames;
      wcxt->cbuffer = cxt->buffers[ch];
      wcxt->ratio = ratio;
      wcxt->stride = 1;
      wcxt->res = res;

      workersEnqueueJob(cxt->workers, resampleProcessChannelJob, wcxt,
                        ch < cxt->numChannels - 1 ? WaitForAvailableWorkerThread
                                                  : DontUseWorkerThread);
    }

    workersWaitAllJobs(cxt->workers);
    res = worker_contexts[0].res;
    *cxt = worker_contexts[0];
    free(worker_contexts);

    return res;
  } else if (cxt->numChannels == 1) {
    if (input) {
      cxt->input = input[0] - 1;
    }
    cxt->numInputFrames = numInputFrames;
    cxt->output = output[0] - 1;
    cxt->numOutputFrames = numOutputFrames;
    cxt->cbuffer = cxt->buffers[0];
    cxt->ratio = ratio;
    cxt->stride = 1;
    cxt->res.output_generated = 0;
    cxt->res.input_used = 0;

    resampleProcessChannelJob(cxt, NULL);
    return cxt->res;
  } else {
#endif
    int half_taps = cxt->numTaps / 2, i;
    ResampleResult res = {0, 0};
    double offset2 = 0.0;
    // Read once: the subsample() call below would make the analyzer forget it.
    const int num_channels = cxt->numChannels;

    if (numInputFrames < 0) { // this is where flush is handled
      postfillAllChannels(cxt);
    }

    while (numOutputFrames > 0) {
      if (cxt->outputOffset + offset2 >= cxt->inputIndex - half_taps) {
        if (numInputFrames > 0) {
          if (cxt->inputIndex == cxt->numSamples) {
            for (i = 0; i < num_channels; ++i) {
              memmove(cxt->buffers[i],
                      cxt->buffers[i] + cxt->numSamples - cxt->numTaps,
                      cxt->numTaps * sizeof(artsample_t));
            }

            cxt->outputOffset -= cxt->numSamples - cxt->numTaps;
            cxt->inputIndex -= cxt->numSamples - cxt->numTaps;
          }

          for (i = 0; i < num_channels; ++i) {
            cxt->buffers[i][cxt->inputIndex] = input[i][res.input_used];
          }

          cxt->inputIndex++;
          res.input_used++;
          numInputFrames--;
        } else {
          break;
        }
      } else {
#ifdef ENABLE_EXTRAPOLATION
        // if we are extrapolating backwards and haven't yet, now is the time
        if (cxt->flags & EXTRAPOLATE_PREFILL) {
          cxt->flags &= ~EXTRAPOLATE_PREFILL;
          prefillAllChannels(cxt);
        }
#endif
        for (i = 0; i < num_channels; ++i) {
          output[i][res.output_generated] = (artsample_t)cxt->subsample(
              cxt, cxt->buffers[i], cxt->outputOffset + offset2);
        }

        offset2 = ++res.output_generated / ratio;
        numOutputFrames--;
      }
    }

    cxt->outputOffset += offset2;

    if (cxt->flags & RESAMPLER_SNAP_OFFSET) {
      cxt->outputOffset = floor(cxt->outputOffset) +
                          floor((cxt->outputOffset - floor(cxt->outputOffset)) *
                                    cxt->numFilters +
                                0.5) /
                              cxt->numFilters;
    }

    return res;
#ifdef ENABLE_THREADS
  }
#endif
}

// This is the "interleaved" version of the resampler where the audio samples
// for different channels are passed in sequence in a single buffer. There is
// also a "non-interleaved" version for independent buffers, which is otherwise
// identical (see above).
//
// If this resampler was created with the resampleFixedRatioInit() function,
// then the "ratio" parameter is ignored and the originally specified conversion
// is performed.

ResampleResult resampleProcessInterleaved(Resample *cxt,
                                          const artsample_t *input,
                                          int numInputFrames,
                                          artsample_t *output,
                                          int numOutputFrames, double ratio) {
  if (cxt->flags & RESAMPLE_FIXED_RATIO) { // override any supplied ratio if
                                           // doing fixed ratio resampling
    ratio = cxt->fixedRatio;
  }

  if (cxt->flags &
      RESAMPLER_FLUSHED) { // ignore new input after flush but before reset
    numInputFrames = 0;
  }

#ifdef ENABLE_THREADS
  if (cxt->workers) {
    Resample *worker_contexts = calloc(cxt->numChannels, sizeof(Resample));
    ResampleResult res = {0, 0};
    int ch;

    for (ch = 0; ch < cxt->numChannels; ++ch) {
      Resample *wcxt = worker_contexts + ch;

      *wcxt = *cxt;
      if (input) {
        wcxt->input = input + ch - cxt->numChannels;
      }
      wcxt->numInputFrames = numInputFrames;
      wcxt->output = output + ch - cxt->numChannels;
      wcxt->numOutputFrames = numOutputFrames;
      wcxt->cbuffer = cxt->buffers[ch];
      wcxt->stride = cxt->numChannels;
      wcxt->ratio = ratio;
      wcxt->res = res;

      workersEnqueueJob(cxt->workers, resampleProcessChannelJob, wcxt,
                        ch < cxt->numChannels - 1 ? WaitForAvailableWorkerThread
                                                  : DontUseWorkerThread);
    }

    workersWaitAllJobs(cxt->workers);
    res = worker_contexts[0].res;
    *cxt = worker_contexts[0];
    free(worker_contexts);

    return res;
  } else if (cxt->numChannels == 1) {
    if (input) {
      cxt->input = input - 1;
    }
    cxt->numInputFrames = numInputFrames;
    cxt->output = output - 1;
    cxt->numOutputFrames = numOutputFrames;
    cxt->cbuffer = cxt->buffers[0];
    cxt->ratio = ratio;
    cxt->stride = 1;
    cxt->res.output_generated = 0;
    cxt->res.input_used = 0;

    resampleProcessChannelJob(cxt, NULL);
    return cxt->res;
  } else {
#endif
    int half_taps = cxt->numTaps / 2, i;
    ResampleResult res = {0, 0};
    double offset2 = 0.0;

    if (numInputFrames < 0) { // this is where flush is handled
      postfillAllChannels(cxt);
    }

    while (numOutputFrames > 0) {
      if (cxt->outputOffset + offset2 >= cxt->inputIndex - half_taps) {
        if (numInputFrames > 0) {
          if (cxt->inputIndex == cxt->numSamples) {
            for (i = 0; i < cxt->numChannels; ++i) {
              memmove(cxt->buffers[i],
                      cxt->buffers[i] + cxt->numSamples - cxt->numTaps,
                      cxt->numTaps * sizeof(artsample_t));
            }

            cxt->outputOffset -= cxt->numSamples - cxt->numTaps;
            cxt->inputIndex -= cxt->numSamples - cxt->numTaps;
          }

          for (i = 0; i < cxt->numChannels; ++i) {
            cxt->buffers[i][cxt->inputIndex] = *input++;
          }

          cxt->inputIndex++;
          res.input_used++;
          numInputFrames--;
        } else {
          break;
        }
      } else {
#ifdef ENABLE_EXTRAPOLATION
        // if we are extrapolating backwards and haven't yet, now is the time
        if (cxt->flags & EXTRAPOLATE_PREFILL) {
          cxt->flags &= ~EXTRAPOLATE_PREFILL;
          prefillAllChannels(cxt);
        }
#endif
        for (i = 0; i < cxt->numChannels; ++i) {
          *output++ = (artsample_t)cxt->subsample(cxt, cxt->buffers[i],
                                                  cxt->outputOffset + offset2);
        }

        offset2 = ++res.output_generated / ratio;
        numOutputFrames--;
      }
    }

    cxt->outputOffset += offset2;

    if (cxt->flags & RESAMPLER_SNAP_OFFSET) {
      cxt->outputOffset = floor(cxt->outputOffset) +
                          floor((cxt->outputOffset - floor(cxt->outputOffset)) *
                                    cxt->numFilters +
                                0.5) /
                              cxt->numFilters;
    }

    return res;
#ifdef ENABLE_THREADS
  }
#endif
}

// This is where we flush the resampler by simulating enough input (half the
// number of filter taps) to align the output. We may fill with zeros, or
// extrapolate the most recent samples if that option is selected.

static void postfillAllChannels(Resample *cxt) {
  int c;

  if (cxt->numSamples - cxt->inputIndex < cxt->numTaps / 2) {
    for (c = 0; c < cxt->numChannels; ++c) {
      memmove(cxt->buffers[c], cxt->buffers[c] + cxt->numSamples - cxt->numTaps,
              cxt->numTaps * sizeof(artsample_t));
    }

    cxt->outputOffset -= cxt->numSamples - cxt->numTaps;
    cxt->inputIndex -= cxt->numSamples - cxt->numTaps;
  }

  for (c = 0; c < cxt->numChannels; ++c) {
    memset(cxt->buffers[c] + cxt->inputIndex, 0,
           (cxt->numSamples - cxt->inputIndex) * sizeof(artsample_t));
#ifdef ENABLE_EXTRAPOLATION
    if (cxt->flags & EXTRAPOLATE_ENDPOINTS) {
      extrapolate_forward(cxt->buffers[c] + cxt->inputIndex - cxt->numTaps / 2,
                          cxt->numTaps / 2, cxt->numTaps / 2);
    }
#endif
  }

  cxt->flags |= RESAMPLER_FLUSHED;
  cxt->inputIndex += cxt->numTaps / 2;
}

// Extrapolate the samples received so far back into the sample buffers.

#ifdef ENABLE_EXTRAPOLATION

static void prefillAllChannels(Resample *cxt) {
  int num_samples = cxt->inputIndex - cxt->numTaps, c;

  if (num_samples >= 8) {
    for (c = 0; c < cxt->numChannels; ++c) {
      extrapolate_reverse(cxt->buffers[c] + cxt->inputIndex, num_samples,
                          cxt->numTaps - num_samples);
    }
  }
}

#endif

// These two convenience functions are extensions of resampleProcess() and
// resampleProcessInterleaved() that additionally perform the final "flush"
// operation on the specified resampler. Simply call them for the last block of
// samples and the "flushed" samples will be appended to the generated output,
// with the total number of samples generated still indicated by the
// "output_generated" field of the ResampleResult. Be sure to have enough buffer
// space available.
//
// Using these is equivalent to calling the regular resampling functions with
// the final block to be resampled and then calling them again with
// numInputFrames set to -1 to execute the flush. This simply combines the two
// calls into one.

ResampleResult resampleProcessAndFlush(Resample *cxt,
                                       const artsample_t *const *input,
                                       int numInputFrames,
                                       artsample_t *const *output,
                                       int numOutputFrames, double ratio) {
  const int num_channels = cxt->numChannels;
  artsample_t **output_array =
      (artsample_t **)calloc(sizeof(artsample_t *), num_channels);
  ResampleResult res = {0, 0}, fres;
  int c;

  for (c = 0; c < num_channels; ++c) {
    output_array[c] = output[c];
  }

  res = resampleProcess(cxt, input, numInputFrames, output_array,
                        numOutputFrames, ratio);

  // if we didn't consume all the input or ran out of output space, we're
  // finished (and this is obviously an unforced error, but the caller will have
  // to sort that out)

  numInputFrames -= (int)res.input_used;
  numOutputFrames -= (int)res.output_generated;
  if (numInputFrames != 0 || numOutputFrames == 0) {
    free((void *)output_array);
    return res;
  }

  for (c = 0; c < num_channels; ++c) {
    output_array[c] += res.output_generated;
  }

  fres = resampleProcess(cxt, NULL, -1, output_array, numOutputFrames, ratio);
  res.output_generated += fres.output_generated;

  free((void *)output_array);
  return res;
}

ResampleResult
resampleProcessAndFlushInterleaved(Resample *cxt, const artsample_t *input,
                                   int numInputFrames, artsample_t *output,
                                   int numOutputFrames, double ratio) {
  ResampleResult res = {0, 0}, fres;

  res = resampleProcessInterleaved(cxt, input, numInputFrames, output,
                                   numOutputFrames, ratio);

  // if we didn't consume all the input or ran out of output space, we're
  // finished (and this is obviously an unforced error, but the caller will have
  // to sort that out)

  numInputFrames -= (int)res.input_used;
  numOutputFrames -= (int)res.output_generated;
  if (numInputFrames != 0 || numOutputFrames == 0) {
    return res;
  }

  output += (size_t)res.output_generated * cxt->numChannels;
  fres =
      resampleProcessInterleaved(cxt, NULL, -1, output, numOutputFrames, ratio);
  res.output_generated += fres.output_generated;

  return res;
}

#ifdef ENABLE_THREADS

// This is the resampler processing function to process a single channel. It can
// be called directly or called from a worker thread (see workers.c) and is used
// for both interleaved and non-interleaved channels (see the "stride" argument
// in the context).

static int resampleProcessChannelJob(void *ptr, void *sync_not_used) {
  Resample *cxt = ptr;
  int half_taps = cxt->numTaps / 2;
  double offset2 = 0.0;

  // This is where we flush the resampler by simulating enough input (half the
  // number of filter taps) to align the output. We may fill with zeros, or
  // extrapolate the most recent samples if that option is selected.

  if (cxt->numInputFrames < 0) {
    if (cxt->numSamples - cxt->inputIndex < cxt->numTaps / 2) {
      memmove(cxt->cbuffer, cxt->cbuffer + cxt->numSamples - cxt->numTaps,
              cxt->numTaps * sizeof(artsample_t));
      cxt->outputOffset -= cxt->numSamples - cxt->numTaps;
      cxt->inputIndex -= cxt->numSamples - cxt->numTaps;
    }

    memset(cxt->cbuffer + cxt->inputIndex, 0,
           (cxt->numSamples - cxt->inputIndex) * sizeof(artsample_t));

#ifdef ENABLE_EXTRAPOLATION
    if (cxt->flags & EXTRAPOLATE_ENDPOINTS) {
      extrapolate_forward(cxt->cbuffer + cxt->inputIndex - cxt->numTaps / 2,
                          cxt->numTaps / 2, cxt->numTaps / 2);
    }
#endif

    cxt->flags |= RESAMPLER_FLUSHED;
    cxt->inputIndex += cxt->numTaps / 2;
  }

  while (cxt->numOutputFrames > 0) {
    if (cxt->outputOffset + offset2 >= cxt->inputIndex - half_taps) {
      if (cxt->numInputFrames > 0) {
        if (cxt->inputIndex == cxt->numSamples) {
          memmove(cxt->cbuffer, cxt->cbuffer + cxt->numSamples - cxt->numTaps,
                  cxt->numTaps * sizeof(artsample_t));
          cxt->outputOffset -= cxt->numSamples - cxt->numTaps;
          cxt->inputIndex -= cxt->numSamples - cxt->numTaps;
        }

        cxt->cbuffer[cxt->inputIndex++] = *(cxt->input += cxt->stride);
        cxt->res.input_used++;
        cxt->numInputFrames--;
      } else {
        break;
      }
    } else {
#ifdef ENABLE_EXTRAPOLATION
      // if we are extrapolating backwards and haven't yet, now is the time
      if (cxt->flags & EXTRAPOLATE_PREFILL) {
        int num_samples = cxt->inputIndex - cxt->numTaps;

        if (num_samples >= 8) {
          extrapolate_reverse(cxt->cbuffer + cxt->inputIndex, num_samples,
                              cxt->numTaps - num_samples);
        }

        cxt->flags &= ~EXTRAPOLATE_PREFILL;
      }
#endif
      *(cxt->output += cxt->stride) =
          cxt->subsample(cxt, cxt->cbuffer, cxt->outputOffset + offset2);
      offset2 = ++(cxt->res.output_generated) / cxt->ratio;
      cxt->numOutputFrames--;
    }
  }

  cxt->outputOffset += offset2;

  if (cxt->flags & RESAMPLER_SNAP_OFFSET) {
    cxt->outputOffset =
        floor(cxt->outputOffset) +
        floor((cxt->outputOffset - floor(cxt->outputOffset)) * cxt->numFilters +
              0.5) /
            cxt->numFilters;
  }

  return 0;
}

#endif

// These two functions are not required for any application, but might be
// useful. Essentially they allow a "dry run" of the resampler to determine
// beforehand how many input samples would be consumed to generate a given
// output, or how many samples would be generated with a given input.
//
// Note that there is a tricky edge-case here for ratios just over 1.0. If a
// query is made as to how many input samples are required to generate a given
// output, that does NOT necessarily mean that exactly that many samples will be
// generated with the indicated input (specifically an extra sample might be
// generated). Therefore it is important to restrict the output with
// numOutputFrames if an exact output count is desired (don't just assume the
// input count can exactly determine the output count).
//
// If this resampler was created with the resampleFixedRatioInit() function,
// then the "ratio" parameter is ignored and the originally specified conversion
// is simulated.

unsigned int resampleGetRequiredSamples(Resample *cxt, int numOutputFrames,
                                        double ratio) {
  int half_taps = cxt->numTaps / 2;
  int input_index = cxt->inputIndex;
  double offset = cxt->outputOffset;
  ResampleResult res = {0, 0};

  if (cxt->flags & RESAMPLE_FIXED_RATIO) { // override any supplied ratio if
                                           // doing fixed ratio resampling
    ratio = cxt->fixedRatio;
  }

  while (numOutputFrames > 0) {
    if (offset >= input_index - half_taps) {
      if (input_index == cxt->numSamples) {
        offset -= cxt->numSamples - cxt->numTaps;
        input_index -= cxt->numSamples - cxt->numTaps;
      }

      input_index++;
      res.input_used++;
    } else {
      offset += (1.0 / ratio);
      numOutputFrames--;
    }
  }

  return res.input_used;
}

unsigned int resampleGetExpectedOutput(Resample *cxt, int numInputFrames,
                                       double ratio) {
  int half_taps = cxt->numTaps / 2;
  int input_index = cxt->inputIndex;
  double offset = cxt->outputOffset;
  ResampleResult res = {0, 0};

  if (cxt->flags & RESAMPLE_FIXED_RATIO) { // override any supplied ratio if
                                           // doing fixed ratio resampling
    ratio = cxt->fixedRatio;
  }

  if (cxt->flags &
      RESAMPLER_FLUSHED) { // ignore new input after flush but before reset
    numInputFrames = 0;
  } else if (numInputFrames < 0) { // also check for this being a flush
    input_index += half_taps;
  }

  while (1) {
    if (offset >= input_index - half_taps) {
      if (numInputFrames > 0) {
        if (input_index == cxt->numSamples) {
          offset -= cxt->numSamples - cxt->numTaps;
          input_index -= cxt->numSamples - cxt->numTaps;
        }

        input_index++;
        numInputFrames--;
      } else {
        break;
      }
    } else {
      offset += (1.0 / ratio);
      res.output_generated++;
    }
  }

  return res.output_generated;
}

// Advance the resampler output without generating any output, with the units
// referenced to the input sample array. This can be used to temporally align
// the output to the input (by specifying half the sinc filter tap width), and
// it can also be used to introduce a phase shift. The resampler cannot be
// reversed. Although not strictly true, for the purpose of this function we
// will not allow subsampling (non-integer advance) without interpolation being
// enabled.

void resampleAdvancePosition(Resample *cxt, double delta) {
  if (delta < 0.0) {
    fprintf(stderr, "resampleAdvancePosition() can only advance forward!\n");
  } else if (!(cxt->flags & SUBSAMPLE_INTERPOLATE) && floor(delta) != delta) {
    fprintf(stderr, "resampleAdvancePosition() cannot advance partial samples "
                    "without interpolation!\n");
  } else {
    cxt->outputOffset += delta;
  }
}

// Get the subsample position of the resampler. This is initialized to zero when
// the resampler is started (or reset) and moves around zero as the resampler
// processes audio. Obtaining this value is generally not required, but can be
// useful for applications that need accurate phase information from the
// resampler such as asynchronous sample rate converter (ASRC) implementations.
// The units are relative to the input samples, and a negative value indicates
// that an output sample is ready (i.e., can be generated with no further input
// read).
//
// To fully understand the meaning of the position value the following C-like
// pseudo-code for the resampler is presented. Note that this code has the
// length of the sinc filters and the actual interpolation abstracted away (like
// they abstracted away from the user of the library):
//
// while (numOutputFrames > 0) {
//     if (position < 0.0) {
//         write (output);
//         numOutputFrames--;
//         position += (1.0 / ratio);
//     }
//     else if (numInputFrames > 0) {
//         read (input);
//         numInputFrames--;
//         position -= 1.0;
//     }
//     else
//         break;
// }

double resampleGetPosition(Resample *cxt) {
  return cxt->outputOffset + (cxt->numTaps / 2.0) - cxt->inputIndex;
}

// Free all resources associated with the resampler context, including the
// context pointer itself. Do not use the context after this call.

void resampleFree(Resample *cxt) {
  if (cxt) {
    int i;

    for (i = 0; i <= cxt->numFilters; ++i) {
      free(cxt->filters[i]);
    }

    free((void *)cxt->filters);

    for (i = 0; i < cxt->numChannels; ++i) {
      free(cxt->buffers[i]);
    }

    free((void *)cxt->buffers);

#ifdef ENABLE_THREADS
    if (cxt->workers) {
      workersDeinit(cxt->workers);
    }
#endif

    free(cxt);
  }
}

// greatest common divisor

static unsigned long gcd(unsigned long a, unsigned long b) {
  while (b) {
    unsigned long t = a % b;
    a = b;
    b = t;
  }

  return a;
}

// This is the basic convolution operation that is the core of the resampler and
// utilizes the bulk of the CPU load (assuming reasonably long filters). The
// first version is the canonical form for reference, followed by two variations
// that are more accurate and incorporate various degrees of parallelization
// that can be utilized by optimizing compilers. Try 'em and use the fastest, or
// rewrite them using SIMD. Note that changing the "sum" variable from a float
// to a double improves the quality somewhat at the possible expense of speed.

#if 0 // Version 1 (canonical, very simple but slow and less accurate, not
      // recommended)
static double apply_filter (artsample_t *A, artsample_t *B, int num_taps)
{
    artsample_t sum = 0.0;

    do sum += *A++ * *B++;
    while (--num_taps);

    return sum;
}
#endif

#if defined(__XTENSA__) && !defined(PATH_WIDTH)
// ESP32/Xtensa: pure float to use hardware FPU (MADD.S), avoid software double
// emulation
static double apply_filter(artsample_t *A, artsample_t *B, int num_taps) {
  float sum = 0.0f;

  do {
    sum += A[0] * B[0];
    A++;
    B++;
  } while (--num_taps);

  return sum;
}

static double apply_filter_precise(artsample_t *A, artsample_t *B,
                                   int num_taps) {
  float sum = 0.0f;

  do {
    sum += *A++ * *B++;
  } while (--num_taps);

  return sum;
}
#elif !defined(_MSC_VER) || defined(__clang__) || defined(__llvm__) || \
    defined(__INTEL_COMPILER) || defined(__INTEL_LLVM_COMPILER)
// Version 2 (outside-in order, more accurate)
// Works well with most compilers but MSVC works better with the next one
// try "-O3 -mavx2 -fno-signed-zeros -fno-trapping-math -fassociative-math"
static double apply_filter(artsample_t *A, artsample_t *B, int num_taps) {
  int i = num_taps - 1;
  artsample_t sum = (artsample_t)0.0;

  do {
    sum += (A[0] * B[0]) + (A[i] * B[i]);
    A++;
    B++;
  } while ((i -= 2) > 0);

  return sum;
}

// For the "precise" version the order is not important, so just letting the
// compiler do all the parallelization seems to work better with gcc and clang

static double apply_filter_precise(artsample_t *A, artsample_t *B,
                                   int num_taps) {
  double sum = 0.0;

  do {
    sum += (double)*A++ * *B++;
  } while (--num_taps);

  return sum;
}

#else
// Version 3 (outside-in order, 2x unrolled loop)
// Works well with MSVC, but others have trouble vectorizing it
static double apply_filter(artsample_t *A, artsample_t *B, int num_taps) {
  int i = num_taps - 1;
  artsample_t sum = (artsample_t)0.0;

  do {
    sum +=
        (A[0] * B[0]) + (A[i] * B[i]) + (A[1] * B[1]) + (A[i - 1] * B[i - 1]);
    A += 2;
    B += 2;
  } while ((i -= 4) > 0);

  return sum;
}

static double apply_filter_precise(artsample_t *A, artsample_t *B,
                                   int num_taps) {
  int i = num_taps - 1;
  double sum = 0.0;

  do {
    sum += ((double)A[0] * B[0]) + ((double)A[i] * B[i]) +
           ((double)A[1] * B[1]) + ((double)A[i - 1] * B[i - 1]);
    A += 2;
    B += 2;
  } while ((i -= 4) > 0);

  return sum;
}

#endif

static void init_filter(Resample *cxt, artsample_t *filter, double fraction) {
  double filter_sum = 0.0, scaler, error;
  const double a0 = 0.35875;
  const double a1 = 0.48829;
  const double a2 = 0.14128;
  const double a3 = 0.01168;
  int i;

  // "dist" is the absolute distance from the sinc maximum to the filter tap to
  // be calculated, in radians "ratio" is that distance divided by half the tap
  // count such that it reaches π at the window extremes

  // Note that with this scaling, the odd terms of the Blackman-Harris
  // calculation appear to be negated with respect to the reference formula
  // version.

  for (i = 0; i < cxt->numTaps; ++i) {
    double dist = fabs((cxt->numTaps / 2 - 1) + fraction - i) * M_PI;
    double ratio = dist / (cxt->numTaps / 2.0);
    double value;

    if (dist != 0.0) {
      value = sin(dist * cxt->lowpassRatio) / (dist * cxt->lowpassRatio);

      if (cxt->flags & BLACKMAN_HARRIS) {
        value *=
            a0 + a1 * cos(ratio) + a2 * cos(2 * ratio) + a3 * cos(3 * ratio);
      } else {
        value *= 0.5 * (1.0 + cos(ratio)); // Hann window
      }
    } else {
      value = 1.0;
    }

    filter_sum += cxt->tempFilter[i] = value;
  }

  // filter should have unity DC gain

  scaler = 1.0 / filter_sum;
  error = 0.0;

  for (i = cxt->numTaps / 2; i < cxt->numTaps;
       i = cxt->numTaps - i - (i >= cxt->numTaps / 2)) {
    filter[i] = (artsample_t)((cxt->tempFilter[i] *= scaler) - error);
    error += filter[i] - cxt->tempFilter[i];
  }
}

static double subsample_no_interpolate(Resample *cxt, artsample_t *source,
                                       double offset) {
  int fi = (int)floor((offset - floor(offset)) * cxt->numFilters + 0.5);

  source += (int)floor(offset);

  if (!(cxt->flags & INCLUDE_LOWPASS) && !(fi % cxt->numFilters)) {
    return source[fi / cxt->numFilters];
  }

  return apply_filter(cxt->filters[fi], source - cxt->numTaps / 2 + 1,
                      cxt->numTaps);
}

static double subsample_interpolate(Resample *cxt, artsample_t *source,
                                    double offset) {
  double frac = offset - floor(offset);
  int fi = (int)floor(frac *= cxt->numFilters);

  frac -= fi;
  source += (int)floor(offset) - cxt->numTaps / 2 + 1;

  return (apply_filter(cxt->filters[fi], source, cxt->numTaps) * (1.0 - frac)) +
         (apply_filter(cxt->filters[fi + 1], source, cxt->numTaps) * frac);
}

static double subsample_no_interpolate_precise(Resample *cxt,
                                               artsample_t *source,
                                               double offset) {
  int fi = (int)floor((offset - floor(offset)) * cxt->numFilters + 0.5);

  source += (int)floor(offset);

  if (!(cxt->flags & INCLUDE_LOWPASS) && !(fi % cxt->numFilters)) {
    return source[fi / cxt->numFilters];
  }

  return apply_filter_precise(cxt->filters[fi], source - cxt->numTaps / 2 + 1,
                              cxt->numTaps);
}

static double subsample_interpolate_precise(Resample *cxt, artsample_t *source,
                                            double offset) {
  double frac = offset - floor(offset);
  int fi = (int)floor(frac *= cxt->numFilters);

  frac -= fi;
  source += (int)floor(offset) - cxt->numTaps / 2 + 1;

  return (apply_filter_precise(cxt->filters[fi], source, cxt->numTaps) *
          (1.0 - frac)) +
         (apply_filter_precise(cxt->filters[fi + 1], source, cxt->numTaps) *
          frac);
}
