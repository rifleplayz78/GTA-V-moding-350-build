#pragma once
#include <string_view>
#include <fstream>

std::string_view LOGFILE = "PackfileLimitAdjusterEnhanced.log";

void Logging(std::string msg);
void ClearLog();