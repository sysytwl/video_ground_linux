#ifndef TEXT_OSD_H
#define TEXT_OSD_H

#include "msp.h"

void text_osd_reset_fc_state();
void text_osd_mark_fc_supported();
bool text_osd_has_fc_data();
void text_osd_render_from_msp(const osd_data_t& osd);

#endif