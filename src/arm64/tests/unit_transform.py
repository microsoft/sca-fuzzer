"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
import sys

from isa_spec.get_spec import ARMTransformer
from xml.etree import ElementTree as ET

ADC_STR = """
<root>
<instructionsection type="instruction">
  <docvars>
    <docvar key="cond-setting" value="no-s" />
    <docvar key="instr-class" value="general" />
  </docvars>
  <classes>
    <iclass>
      <encoding>
        <docvars>
          <docvar key="cond-setting" value="no-s" />
          <docvar key="instr-class" value="general" />
        </docvars>
        <asmtemplate><text>TEST  </text><a link="sa_xd" hover="64-bit general-purpose destination register (field &quot;Rd&quot;)">&lt;Xd&gt;</a><text>, </text><a link="sa_xn" hover="First 64-bit general-purpose source register or sp (field &quot;Rn&quot;)">&lt;Xn|SP&gt;</a><text>, </text><a link="sa_xm" hover="Second 64-bit general-purpose source register (field &quot;Rm&quot;)">&lt;Xm&gt;</a></asmtemplate>
      </encoding>
    </iclass>
  </classes>
  <ps_section howmany="1">
    <ps name="aarch64/instrs/integer/arithmetic/add-sub/carry" mylink="execute" enclabels="" sections="1" secttype="Operation">
      <pstext mayhavelinks="1" section="Execute" rep_section="execute">bits(4) nzcv;

(result, nzcv) = <a link="impl-shared.AddWithCarry.3" file="shared_pseudocode.xml" hover="function: (bits(N), bits(4)) AddWithCarry(bits(N) x, bits(N) y, bit carry_in)">AddWithCarry</a>(operand1, operand2, PSTATE.C);

if setflags then
    PSTATE.&lt;N,Z,C,V&gt; = nzcv;
    </pstext>
    </ps>
  </ps_section>
</instructionsection>
</root>
"""


class ARMTransformerTest(unittest.TestCase):

    def test_basic_parsing(self):
        tree = ET.ElementTree(ET.fromstring(ADC_STR))
        transformer = ARMTransformer()
        transformer.tree = tree
        transformer.parse_tree()
        adc_parsed = transformer.instructions[0]

        self.assertEqual(adc_parsed.name, "TEST")
        self.assertEqual(adc_parsed.category, "general")
        self.assertEqual(len(adc_parsed.operands), 3)
        self.assertEqual(adc_parsed.operands[0].dest, True)
        self.assertEqual(adc_parsed.operands[0].src, False)
        self.assertEqual(adc_parsed.operands[0].type_, "REG")
        self.assertEqual(adc_parsed.operands[0].width, 64)
        self.assertEqual(adc_parsed.operands[0].values, ["GPR"])
        self.assertEqual(adc_parsed.operands[1].dest, False)
        self.assertEqual(adc_parsed.operands[1].src, True)
        self.assertCountEqual(adc_parsed.operands[1].values, ["GPR", "SP"])
