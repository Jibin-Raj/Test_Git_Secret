#pragma once

#include <binary_data.h>
#include <ltts/iot/security/digital_id.h>
#include <ltts/iot/security/iotsec_api.h>

#include <cstddef>
#include <string>
#include <tuple>

#define TESTDATA_ACTIVATIONTOKEN_FOR_SERVER                                                       \
	R"(eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhbXFwdXJpIjoiYW1xcDovLzE5Mi4xNjguMS44OjU2NzIiLCJhdWQiOiJ7XCJhY2NvdW50X2lkXCI6MSxcImVudGl0eV90eXBlXCI6XCJ1c2VyXCIsXCJlbnRpdHlfaWRcIjoxfSIsImV4cCI6MTU5NDIxMjk1NCwiZm90YXVyaSI6Imh0dHA6Ly8xOTIuMTY4LjEuODo4MDgwL3Yke3tWRVJTSU9OfX0vZm90YSIsImlhbXVyaSI6Imh0dHA6Ly8xOTIuMTY4LjEuODo4MDgwL3Yke3tWRVJTSU9OfX0vaWFtIiwiaWF0IjoxNTk0MjA5Mjk0LCJpc3MiOiJJQU0ifQ.YElXuHPgeregNToUYBLCk2_UiAcZ_9BXZMvLGoVbnFR3286_eZFYvDwE9m2P9WhjBr-vsEFpzvdVlt4y9AwS0powm3olsdJMcL0kkvfShkYTcDfH3-OU14oBjJYUFvSWZ-ryWYKxg-Zuu438LJlr3WZWlg3y4xH-PixVr3vHhmgg01IEY9JzgxTKF2__ekF78DAPwktK-VJE6VoXbz02j5WrXeDX2fPw9Yv1o4ExbmEvknW5Kf4VrcluUup8-vSdAhkZoZ5X1Y1rDUVrXhRb75h5tgDvx5T3Qr_IVP5QcJwVtL10mI8G5i68Zw80Yya9dQlR4_WMecnzphRB1i7OXA)"

namespace ltts::iot::security::detail
{

/** Build the allocated memory and pointer to an `iotsec_iam_activation_token`, using data that is
 * usable in a live server for system testing. */
std::tuple<std::string, struct iotsec_iam_activation_token>
TESTDATA_build_activation_token_for_server();

/** Build the allocated memory and pointer to the key and encrypted secret that can be decrypted by
 * the Digital ID of this computer (whichever you are running on) - the key+secret must be usable
 * on the server specified in the activation token.
 */
std::tuple<std::string, ltts::iot::security::detail::Binary_data>
TESTDATA_build_key_and_encrypted_secret_for_server();

std::tuple<ltts::iot::security::Digital_id, std::string, ltts::iot::security::detail::Binary_data>
TESTDATA_build_key_and_encrypted_with_digital_id();

struct iotsec_iam_credentials
TESTDATA_make_creds_with_pointers( std::string const& key,
                                   ltts::iot::security::detail::Binary_data const& encrypted );

} // namespace ltts::iot::security::detail
