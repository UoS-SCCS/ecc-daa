/******************************************************************************
* File:        mechanism_4_data.h
* Description: Data from ISO mechanism 4 (parameters for EC curve bnp256 given
*              separately)
*
* Author:      Chris Newton
*
* Created:     Friday 3 August 2018
*
*
******************************************************************************/

#pragma once

#include "Byte_buffer.h"
#include "G2_utils.h"

/* Extracted from ISO DAA Mechanism 4

P2 = Generator for G_2 curve
E20171C5 4AA3DA05 21670413 743CCF22 D25D5268 3D32470E F6021343 BF282394
592D1EF6 53A85A80 46CCDC25 4FBB5656 43433BF6 289653E2 7DF7B212 BAA189BE
AE60A4E7 51FFD350 C621E703 312826BD 55E8B59A 4D916838 414DB822 DD2335AE
1AB442F9 89AFE5AD F80274F8 7645E253 2CDC6181 9093D613 2C90FE89 51B92421
*/

const Hex_string hex_p2_x0("E20171C54AA3DA0521670413743CCF22D25D52683D32470EF6021343BF282394");
const Byte_buffer iso_p2_x0(hex_p2_x0);
const Hex_string hex_p2_x1("592D1EF653A85A8046CCDC254FBB565643433BF6289653E27DF7B212BAA189BE");
const Byte_buffer iso_p2_x1(hex_p2_x1);

const G2_coord iso_p2_x=std::make_pair(iso_p2_x0,iso_p2_x1);

const Hex_string hex_p2_y0("AE60A4E751FFD350C621E703312826BD55E8B59A4D916838414DB822DD2335AE");
const Byte_buffer iso_p2_y0(hex_p2_y0);
const Hex_string hex_p2_y1("1AB442F989AFE5ADF80274F87645E2532CDC61819093D6132C90FE8951B92421");
const Byte_buffer iso_p2_y1(hex_p2_y1);

const G2_coord iso_p2_y=std::make_pair(iso_p2_y0,iso_p2_y1);

const G2_point iso_p2=std::make_pair(iso_p2_x,iso_p2_y);

/* Test examples for G_2 curve

Public keys for Issuer:
X =
81ECB895 667EA4F9 F37193F1 EE91968D 0E1677D8 42C9D98C 0731486 D1797A492
0F31D669 D93543F9 23484F76 3EB07485 EAD88D90 EB277476 7F4A599 00253F849
FF83F12E 98791CA7 63A900A8 94CF2690 6E42CAB4 E96B614D 2E2F468 1B7B5D1B1
BC97D3BD F100EC4B 16635FA0 3B4959B5 58ADEF4D BE6D8904 0CFC739 9A294195F
Y =
A7F6DBE3 D5FE924C 92B87B9C 87D25132 FB464A8B 48032A70 DFD4844 B588FE585
504147A8 64F90C5C B22C49D3 2B9357CA 51760D52 621CB632 50D522E AAB9BB271
0910BEEA 0B55068B EAE74888 75A02E51 46B37C9C DEC6B2B7 C74FCA2 9E2ED2AAB
4E148283 F3E99483 8A24F2C6 903EE6BD E99EEFED F2D137F6 3BDED47 BE46297A8

Private keys for issuer:
x =
65A9BF91 AC883237 9FF04DD2 C6DEF16D 48A56BE2 44F6E192 74E9788 1A776543C
y =
126F7425 8BB0CECA 2AE7522C 51825F98 0549EC1E F24F81D1 89D17E38 F1773B56

*/
const Hex_string hex_sk_x("65A9BF91AC8832379FF04DD2C6DEF16D48A56BE244F6E19274E97881A776543C");
const Byte_buffer iso_sk_x(hex_sk_x);

const Hex_string hex_pk_x_x0("A7F6DBE3D5FE924C92B87B9C87D25132FB464A8B48032A70DFD4844B588FE585");
const Byte_buffer iso_pk_x_x0(hex_pk_x_x0);

const Hex_string hex_pk_x_x1("504147A864F90C5CB22C49D32B9357CA51760D52621CB63250D522EAAB9BB271");
const Byte_buffer iso_pk_x_x1(hex_pk_x_x1);

const G2_coord iso_pk_x_x=std::make_pair(iso_pk_x_x0,iso_pk_x_x1);

const Hex_string hex_pk_x_y0("0910BEEA0B55068BEAE7488875A02E5146B37C9CDEC6B2B7C74FCA29E2ED2AAB");
const Byte_buffer iso_pk_x_y0(hex_pk_x_y0);

const Hex_string hex_pk_x_y1("4E148283F3E994838A24F2C6903EE6BDE99EEFEDF2D137F63BDED47BE46297A8");
const Byte_buffer iso_pk_x_y1(hex_pk_x_y1);

const G2_coord iso_pk_x_y=std::make_pair(iso_pk_x_y0,iso_pk_x_y1);

const G2_point iso_pk_x=std::make_pair(iso_pk_x_x,iso_pk_x_y);

const Hex_string hex_sk_y("126F74258BB0CECA2AE7522C51825F980549EC1EF24F81D189D17E38F1773B56");
const Byte_buffer iso_sk_y(hex_sk_y);

const Hex_string hex_pk_y_x0("81ECB895667EA4F9F37193F1EE91968D0E1677D842C9D98C0731486D1797A492");
const Byte_buffer iso_pk_y_x0(hex_pk_y_x0);

const Hex_string hex_pk_y_x1("0F31D669D93543F923484F763EB07485EAD88D90EB2774767F4A59900253F849");
const Byte_buffer iso_pk_y_x1(hex_pk_y_x1);

const G2_coord iso_pk_y_x=std::make_pair(iso_pk_y_x0,iso_pk_y_x1);

const Hex_string hex_pk_y_y0("FF83F12E98791CA763A900A894CF26906E42CAB4E96B614D2E2F4681B7B5D1B1");
const Byte_buffer iso_pk_y_y0(hex_pk_y_y0);

const Hex_string hex_pk_y_y1("BC97D3BDF100EC4B16635FA03B4959B558ADEF4DBE6D89040CFC7399A294195F");
const Byte_buffer iso_pk_y_y1(hex_pk_y_y1);

const G2_coord iso_pk_y_y=std::make_pair(iso_pk_y_y0,iso_pk_y_y1);

const G2_point iso_pk_y=std::make_pair(iso_pk_y_x,iso_pk_y_y);

