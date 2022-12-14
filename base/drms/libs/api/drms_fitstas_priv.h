#ifndef _DRMS_FITSTAS_PRIV_H
#define _DRMS_FITSTAS_PRIV_H

#include "drms.h"

int drms_fitstas_create(DRMS_Env_t *env,
                        const char *filename, 
                        const char *comp,
                        DRMS_Type_t type, 
                        int naxis, 
                        int *axis,
                        double bzero,
                        double bscale);

int drms_fitstas_readslice(DRMS_Env_t *env,
                           const char *filename, 
                           int naxis,
                           int *axis,
                           int *lower,
                           int *upper,
                           int slotnum,
                           DRMS_Array_t **arr);

int drms_fitstas_writeslice(DRMS_Env_t *env,
                            DRMS_Segment_t *seg,
                            const char *filename, 
                            int naxis,
                            int *axis,
                            int *lower,
                            int *upper,
                            int slotnum,
                            DRMS_Array_t *arrayout);

#endif /* _DRMS_FITSTAS_PRIV_H */
