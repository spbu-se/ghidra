/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.program.database.data;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.*;

import com.google.common.collect.Sets;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.StubMemory;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.InvalidNameException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class StructureDBTest extends AbstractGenericTest {

	private StructureDB struct;
	private StandAloneDataTypeManager dataMgr;
	private int txId;

	@Before
	public void setUp() throws Exception {

		dataMgr = new StandAloneDataTypeManager("dummyDTM");

		// default data organization is little-endian
		// default BitFieldPackingImpl uses gcc conventions with type alignment enabled

		txId = dataMgr.startTransaction("Test");

		struct = createStructure("Test", 0);
		struct.add(new ByteDataType(), "field1", "Comment1");
		struct.add(new WordDataType(), null, "Comment2");
		struct.add(new DWordDataType(), "field3", null);
		struct.add(new ByteDataType(), "field4", "Comment4");

	}

	@After
	public void tearDown() {
		if (dataMgr != null) {
			dataMgr.endTransaction(txId, true);
			dataMgr.close();
		}
	}

	private void transitionToBigEndian() {

		Structure structClone = struct.clone(null);
		dataMgr.remove(struct, TaskMonitor.DUMMY);

		DataOrganizationImpl dataOrg = (DataOrganizationImpl) dataMgr.getDataOrganization();
		dataOrg.setBigEndian(true);

		// re-resolve with modified endianness
		struct = (StructureDB) dataMgr.resolve(structClone, null);
	}

	private StructureDB createStructure(String name, int length) {
		return (StructureDB) dataMgr.resolve(new StructureDataType(name, length), null);
	}

	private Union createUnion(String name) {
		Union unionDt = new UnionDataType(name);
		return (Union) dataMgr.addDataType(unionDt, DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	private TypeDef createTypeDef(DataType dataType) {
		return (TypeDef) dataMgr
				.resolve(new TypedefDataType(dataType.getName() + "TypeDef", dataType), null);
	}

	private Array createArray(DataType dataType, int numElements) {
		return (Array) dataMgr
				.resolve(new ArrayDataType(dataType, numElements, dataType.getLength()), null);
	}

	private Pointer createPointer(DataType dataType, int length) {
		return (Pointer) dataMgr.resolve(new Pointer32DataType(dataType), null);
	}
	
	private ByteMemBufferImpl mb(int... values) {
		GenericAddressSpace gas = new GenericAddressSpace("test", 32, AddressSpace.TYPE_RAM, 1);
		Memory mem = new TestMemory(gas.getMinAddress(), gas.getMaxAddress());
		return new ByteMemBufferImpl(mem, gas.getAddress(0), bytes(values), false);
	}
	
	private static class TestMemory extends StubMemory
	{
		private Address minAddress;
		private Address maxAddress;
		
		public TestMemory(Address minAddr, Address maxAddr)
		{
			minAddress = minAddr;
			maxAddress = maxAddr;
		}

		@Override
	    public AddressSet getAllInitializedAddressSet() {
	        return new AddressSet(minAddress, maxAddress);
	    }
	}

	@Test
	public void testEmpty() throws Exception {
		Structure s = new StructureDataType("foo", 0);
		assertTrue(s.isNotYetDefined());
		assertTrue(s.isZeroLength());
		assertEquals(0, s.getNumComponents());
		assertEquals(0, s.getNumDefinedComponents());
		Structure s2 = (Structure) dataMgr.resolve(s, null);
		assertTrue(s2.isNotYetDefined());
		assertTrue(s2.isZeroLength());
		assertEquals(0, s2.getNumComponents());
		assertEquals(0, s.getNumDefinedComponents());
	}

	@Test
	public void testSizeOne() throws Exception {
		Structure s = new StructureDataType("foo", 1);
		assertFalse(s.isNotYetDefined());
		assertFalse(s.isZeroLength());
		assertEquals(1, s.getNumComponents());
		assertEquals(0, s.getNumDefinedComponents());
		Structure s2 = (Structure) dataMgr.resolve(s, null);
		assertFalse(s2.isNotYetDefined());
		assertFalse(s2.isZeroLength());
		assertEquals(1, s2.getNumComponents());
		assertEquals(0, s2.getNumDefinedComponents());
	}

	@Test
	public void testAdd() throws Exception {
		assertEquals(8, struct.getLength());
		assertEquals(4, struct.getNumComponents());

		DataTypeComponent dtc = struct.getComponent(0);
		assertEquals(0, dtc.getOffset());
		assertEquals(0, dtc.getOrdinal());
		assertEquals("field1", dtc.getFieldName());
		assertEquals("Comment1", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(1);
		assertEquals(1, dtc.getOffset());
		assertEquals(1, dtc.getOrdinal());
		assertNull(dtc.getFieldName());
		assertEquals("Comment2", dtc.getComment());
		assertEquals(WordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(2);
		assertEquals(3, dtc.getOffset());
		assertEquals(2, dtc.getOrdinal());
		assertEquals("field3", dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(3);
		assertEquals(7, dtc.getOffset());
		assertEquals(3, dtc.getOrdinal());
		assertEquals("field4", dtc.getFieldName());
		assertEquals("Comment4", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

	}

	@Test
	public void testAdd2() throws Exception {
		struct = createStructure("Test", 10);

		assertEquals(10, struct.getLength());
		assertEquals(10, struct.getNumComponents());

		struct.add(new ByteDataType(), "field1", "Comment1");
		struct.add(new WordDataType(), "field1", "Comment2");
		struct.add(new DWordDataType(), "field3", null);
		struct.add(new ByteDataType(), "field4", "Comment4");

		assertEquals(18, struct.getLength());
		assertEquals(14, struct.getNumComponents());

		DataTypeComponent dtc = struct.getComponent(0);
		assertEquals(0, dtc.getOffset());
		assertEquals(0, dtc.getOrdinal());
		assertNull(dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(DataType.DEFAULT, dtc.getDataType());

		dtc = struct.getComponent(1);
		assertEquals(1, dtc.getOffset());
		assertEquals(1, dtc.getOrdinal());
		assertNull(dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(DataType.DEFAULT, dtc.getDataType());

		dtc = struct.getComponent(10);
		assertEquals(10, dtc.getOffset());
		assertEquals(10, dtc.getOrdinal());
		assertEquals("field1", dtc.getFieldName());
		assertEquals("Comment1", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(11);
		assertEquals(11, dtc.getOffset());
		assertEquals(11, dtc.getOrdinal());
		assertEquals("field1", dtc.getFieldName());
		assertEquals("Comment2", dtc.getComment());
		assertEquals(WordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(12);
		assertEquals(13, dtc.getOffset());
		assertEquals(12, dtc.getOrdinal());
		assertEquals("field3", dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());
	}

	@Test
	public void testInsert_beginning() {
		struct.insert(0, new FloatDataType());
		assertEquals(12, struct.getLength());
		assertEquals(5, struct.getNumComponents());

		DataTypeComponent dtc = struct.getComponent(0);
		assertEquals(0, dtc.getOffset());
		assertEquals(0, dtc.getOrdinal());
		assertEquals(null, dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(FloatDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(1);
		assertEquals(4, dtc.getOffset());
		assertEquals(1, dtc.getOrdinal());
		assertEquals("field1", dtc.getFieldName());
		assertEquals("Comment1", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(2);
		assertEquals(5, dtc.getOffset());
		assertEquals(2, dtc.getOrdinal());
		assertNull(dtc.getFieldName());
		assertEquals("Comment2", dtc.getComment());
		assertEquals(WordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(3);
		assertEquals(7, dtc.getOffset());
		assertEquals(3, dtc.getOrdinal());
		assertEquals("field3", dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(4);
		assertEquals(11, dtc.getOffset());
		assertEquals(4, dtc.getOrdinal());
		assertEquals("field4", dtc.getFieldName());
		assertEquals("Comment4", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

	}

	@Test
	public void testInsert_end() {
		struct.insert(4, new FloatDataType());
		assertEquals(12, struct.getLength());
		assertEquals(5, struct.getNumComponents());

		DataTypeComponent dtc = struct.getComponent(0);
		assertEquals(0, dtc.getOffset());
		assertEquals(0, dtc.getOrdinal());
		assertEquals("field1", dtc.getFieldName());
		assertEquals("Comment1", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(1);
		assertEquals(1, dtc.getOffset());
		assertEquals(1, dtc.getOrdinal());
		assertEquals(null, dtc.getFieldName());
		assertEquals("Comment2", dtc.getComment());
		assertEquals(WordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(2);
		assertEquals(3, dtc.getOffset());
		assertEquals(2, dtc.getOrdinal());
		assertEquals("field3", dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(3);
		assertEquals(7, dtc.getOffset());
		assertEquals(3, dtc.getOrdinal());
		assertEquals("field4", dtc.getFieldName());
		assertEquals("Comment4", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(4);
		assertEquals(8, dtc.getOffset());
		assertEquals(4, dtc.getOrdinal());
		assertNull(dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(FloatDataType.class, dtc.getDataType().getClass());

	}

	@Test
	public void testInsert_middle() {
		struct.insert(2, new FloatDataType());
		assertEquals(12, struct.getLength());
		assertEquals(5, struct.getNumComponents());

		DataTypeComponent dtc = struct.getComponent(0);
		assertEquals(0, dtc.getOffset());
		assertEquals(0, dtc.getOrdinal());
		assertEquals("field1", dtc.getFieldName());
		assertEquals("Comment1", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(1);
		assertEquals(1, dtc.getOffset());
		assertEquals(1, dtc.getOrdinal());
		assertNull(dtc.getFieldName());
		assertEquals("Comment2", dtc.getComment());
		assertEquals(WordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(2);
		assertEquals(3, dtc.getOffset());
		assertEquals(2, dtc.getOrdinal());
		assertNull(dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(FloatDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(3);
		assertEquals(7, dtc.getOffset());
		assertEquals(3, dtc.getOrdinal());
		assertEquals("field3", dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(4);
		assertEquals(11, dtc.getOffset());
		assertEquals(4, dtc.getOrdinal());
		assertEquals("field4", dtc.getFieldName());
		assertEquals("Comment4", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());
	}

	@Test
	public void testInsertWithEmptySpace() {
		struct = createStructure("Test", 100);
		struct.insert(40, new ByteDataType());
		struct.insert(20, new WordDataType());

		struct.insert(10, new FloatDataType());

		assertEquals(107, struct.getLength());
		assertEquals(103, struct.getNumComponents());

		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(3, comps.length);

		assertEquals(10, comps[0].getOffset());
		assertEquals(10, comps[0].getOrdinal());
		assertEquals(FloatDataType.class, comps[0].getDataType().getClass());

		assertEquals(24, comps[1].getOffset());
		assertEquals(21, comps[1].getOrdinal());
		assertEquals(WordDataType.class, comps[1].getDataType().getClass());

		assertEquals(46, comps[2].getOffset());
		assertEquals(42, comps[2].getOrdinal());
		assertEquals(ByteDataType.class, comps[2].getDataType().getClass());
	}

	// test inserting at offset 0
	@Test
	public void testInsertAtOffset() {
		struct.insertAtOffset(0, new FloatDataType(), 4);
		assertEquals(12, struct.getLength());
		DataTypeComponent[] comps = struct.getDefinedComponents();

		assertEquals(5, comps.length);

		assertEquals(0, comps[0].getOffset());
		assertEquals(0, comps[0].getOrdinal());
		assertEquals(FloatDataType.class, comps[0].getDataType().getClass());

		assertEquals(4, comps[1].getOffset());
		assertEquals(1, comps[1].getOrdinal());
		assertEquals(ByteDataType.class, comps[1].getDataType().getClass());

		assertEquals(5, comps[2].getOffset());
		assertEquals(2, comps[2].getOrdinal());
		assertEquals(WordDataType.class, comps[2].getDataType().getClass());

		assertEquals(7, comps[3].getOffset());
		assertEquals(3, comps[3].getOrdinal());
		assertEquals(DWordDataType.class, comps[3].getDataType().getClass());

	}

	// test inserting at offset 1
	@Test
	public void testInsertAtOffset1() {
		struct.insertAtOffset(1, new FloatDataType(), 4);
		assertEquals(12, struct.getLength());

		DataTypeComponent[] comps = struct.getDefinedComponents();

		assertEquals(5, comps.length);

		assertEquals(0, comps[0].getOffset());
		assertEquals(0, comps[0].getOrdinal());
		assertEquals(ByteDataType.class, comps[0].getDataType().getClass());

		assertEquals(1, comps[1].getOffset());
		assertEquals(1, comps[1].getOrdinal());
		assertEquals(FloatDataType.class, comps[1].getDataType().getClass());

		assertEquals(5, comps[2].getOffset());
		assertEquals(2, comps[2].getOrdinal());
		assertEquals(WordDataType.class, comps[2].getDataType().getClass());

		assertEquals(7, comps[3].getOffset());
		assertEquals(3, comps[3].getOrdinal());
		assertEquals(DWordDataType.class, comps[3].getDataType().getClass());

	}

	// test inserting at offset 2
	@Test
	public void testInsertAtOffset2() {
		struct.insertAtOffset(2, new FloatDataType(), 4);
		assertEquals(13, struct.getLength());

		DataTypeComponent[] comps = struct.getDefinedComponents();

		assertEquals(5, comps.length);

		assertEquals(0, comps[0].getOffset());
		assertEquals(0, comps[0].getOrdinal());
		assertEquals(ByteDataType.class, comps[0].getDataType().getClass());

		assertEquals(2, comps[1].getOffset());
		assertEquals(2, comps[1].getOrdinal());
		assertEquals(FloatDataType.class, comps[1].getDataType().getClass());

		assertEquals(6, comps[2].getOffset());
		assertEquals(3, comps[2].getOrdinal());
		assertEquals(WordDataType.class, comps[2].getDataType().getClass());

		assertEquals(8, comps[3].getOffset());
		assertEquals(4, comps[3].getOrdinal());
		assertEquals(DWordDataType.class, comps[3].getDataType().getClass());

	}

	@Test
	public void testInsertWithZeroArrayAtOffset() {
		struct.insertAtOffset(2, FloatDataType.dataType, -1);
		Array zeroArray = new ArrayDataType(FloatDataType.dataType, 0, -1);
		struct.insertAtOffset(2, zeroArray, -1);
		assertEquals(13, struct.getLength());

		DataTypeComponent[] comps = struct.getDefinedComponents();

		assertEquals(6, comps.length);

		assertEquals(0, comps[0].getOffset());
		assertEquals(0, comps[0].getOrdinal());
		assertEquals(ByteDataType.class, comps[0].getDataType().getClass());

		assertEquals(2, comps[1].getOffset());
		assertEquals(2, comps[1].getOrdinal());
		assertTrue(zeroArray.isEquivalent(comps[1].getDataType()));

		assertEquals(2, comps[2].getOffset());
		assertEquals(3, comps[2].getOrdinal());
		assertEquals(FloatDataType.class, comps[2].getDataType().getClass());

		assertEquals(6, comps[3].getOffset());
		assertEquals(4, comps[3].getOrdinal());
		assertEquals(WordDataType.class, comps[3].getDataType().getClass());

		assertEquals(8, comps[4].getOffset());
		assertEquals(5, comps[4].getOrdinal());
		assertEquals(DWordDataType.class, comps[4].getDataType().getClass());

	}

	@Test
	public void testInsertWithZeroArrayAtOffset2() {
		Array zeroArray = new ArrayDataType(FloatDataType.dataType, 0, -1);
		struct.insertAtOffset(2, zeroArray, -1);
		struct.insertAtOffset(2, FloatDataType.dataType, -1);
		assertEquals(13, struct.getLength());

		DataTypeComponent[] comps = struct.getDefinedComponents();

		assertEquals(6, comps.length);

		assertEquals(0, comps[0].getOffset());
		assertEquals(0, comps[0].getOrdinal());
		assertEquals(ByteDataType.class, comps[0].getDataType().getClass());

		assertEquals(2, comps[1].getOffset());
		assertEquals(2, comps[1].getOrdinal());
		assertEquals(FloatDataType.class, comps[1].getDataType().getClass());

		assertEquals(6, comps[2].getOffset());
		assertEquals(3, comps[2].getOrdinal());
		assertTrue(zeroArray.isEquivalent(comps[2].getDataType()));

		assertEquals(6, comps[3].getOffset());
		assertEquals(4, comps[3].getOrdinal());
		assertEquals(WordDataType.class, comps[3].getDataType().getClass());

		assertEquals(8, comps[4].getOffset());
		assertEquals(5, comps[4].getOrdinal());
		assertEquals(DWordDataType.class, comps[4].getDataType().getClass());

	}

	@Test
	public void testInsertAtOffsetPastEnd() {
		struct.insertAtOffset(100, new FloatDataType(), 4);
		assertEquals(104, struct.getLength());
	}

	@Test
	public void testSetFlexArray() throws Exception {

		struct.setPackingEnabled(true);

		struct.delete(2); // remove dword to verify flex array alignment below

		DataTypeComponent flexDtc =
			struct.add(new ArrayDataType(CharDataType.dataType, 0, -1), "flex", "FlexComment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack()\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   2   word   2      \"Comment2\"\n" + 
			"   4   byte   1   field4   \"Comment4\"\n" + 
			"   5   char[0]   0   flex   \"FlexComment\"\n" + 
			"}\n" + 
			"Length: 6 Alignment: 2", struct);
		//@formatter:on

		struct.replace(flexDtc.getOrdinal(), new ArrayDataType(IntegerDataType.dataType, 0, -1), 0,
			"flex", "FlexComment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack()\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   2   word   2      \"Comment2\"\n" + 
			"   4   byte   1   field4   \"Comment4\"\n" + 
			"   8   int[0]   0   flex   \"FlexComment\"\n" + 
			"}\n" + 
			"Length: 8 Alignment: 4", struct);
		//@formatter:on
	}

	@Test
	public void testZeroBitFields() throws Exception {

		struct.setPackingEnabled(true);

		struct.delete(2); // remove dword to verify flex array alignment below

		struct.insertBitField(0, 0, 0, IntegerDataType.dataType, 3, "bf2", "bf1Comment");
		struct.insertBitField(0, 0, 0, IntegerDataType.dataType, 3, "bf1", "bf1Comment");
		struct.insertBitField(1, 0, 0, IntegerDataType.dataType, 0, "z1", "zero bitfield 1");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack()\n" + 
			"Structure Test {\n" + 
			"   0   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   4   int:0(0)   0      \"zero bitfield 1\"\n" + 
			"   4   int:3(0)   1   bf2   \"bf1Comment\"\n" + 
			"   5   byte   1   field1   \"Comment1\"\n" + 
			"   6   word   2      \"Comment2\"\n" + 
			"   8   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 12 Alignment: 4", struct);
		//@formatter:on

		struct.insertBitField(2, 0, 0, IntegerDataType.dataType, 0, "z2", "zero bitfield 2");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack()\n" + 
			"Structure Test {\n" + 
			"   0   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   4   int:0(0)   0      \"zero bitfield 1\"\n" + 
			"   4   int:0(0)   0      \"zero bitfield 2\"\n" + 
			"   4   int:3(0)   1   bf2   \"bf1Comment\"\n" + 
			"   5   byte   1   field1   \"Comment1\"\n" + 
			"   6   word   2      \"Comment2\"\n" + 
			"   8   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 12 Alignment: 4", struct);
		//@formatter:on
	}

	@Test
	public void testInsertBitFieldLittleEndianAppend() throws Exception {

		struct.insertBitField(4, 4, 0, IntegerDataType.dataType, 3, "bf1", "bf1Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2      \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
			"   8   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
//			"   9   undefined   1      \"\"\n" + 
//			"   10   undefined   1      \"\"\n" + 
//			"   11   undefined   1      \"\"\n" + 
			"}\n" + 
			"Length: 12 Alignment: 1", struct);
		//@formatter:on

		struct.insertBitField(4, 4, 3, IntegerDataType.dataType, 3, "bf2", "bf2Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2      \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
			"   8   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   8   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
//			"   9   undefined   1      \"\"\n" + 
//			"   10   undefined   1      \"\"\n" + 
//			"   11   undefined   1      \"\"\n" + 
			"}\n" + 
			"Length: 12 Alignment: 1", struct);
		//@formatter:on

		struct.insertBitField(6, 1, 0, ByteDataType.dataType, 3, "bf3", "bf3Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2      \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
			"   8   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   8   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
			"   9   byte:3(0)   1   bf3   \"bf3Comment\"\n" + 
//			"   10   undefined   1      \"\"\n" + 
//			"   11   undefined   1      \"\"\n" + 
			"}\n" + 
			"Length: 12 Alignment: 1", struct);
		//@formatter:on
	}

	@Test
	public void testInsertBitFieldAtLittleEndianAppend() throws Exception {

		struct.insertBitFieldAt(10, 4, 0, IntegerDataType.dataType, 3, "bf1", "bf1Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2      \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
//			"   8   undefined   1      \"\"\n" + 
//			"   9   undefined   1      \"\"\n" + 
			"   10   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
//			"   11   undefined   1      \"\"\n" + 
//			"   12   undefined   1      \"\"\n" + 
//			"   13   undefined   1      \"\"\n" + 
			"}\n" + 
			"Length: 14 Alignment: 1", struct);
		//@formatter:on

		struct.insertBitFieldAt(10, 4, 3, IntegerDataType.dataType, 3, "bf2", "bf2Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2      \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
//			"   8   undefined   1      \"\"\n" + 
//			"   9   undefined   1      \"\"\n" + 
			"   10   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   10   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
//			"   11   undefined   1      \"\"\n" + 
//			"   12   undefined   1      \"\"\n" + 
//			"   13   undefined   1      \"\"\n" + 
			"}\n" + 
			"Length: 14 Alignment: 1", struct);
		//@formatter:on
	}

	@Test
	public void testInsertBitFieldAtLittleEndian() throws Exception {

		struct.insertBitFieldAt(2, 4, 0, IntegerDataType.dataType, 3, "bf1", "bf1Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
//			"   3   undefined   1      \"\"\n" + 
//			"   4   undefined   1      \"\"\n" + 
//			"   5   undefined   1      \"\"\n" + 
			"   6   word   2      \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 13 Alignment: 1", struct);
		//@formatter:on

		struct.insertBitFieldAt(2, 4, 3, IntegerDataType.dataType, 3, "bf2", "bf2Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
//			"   3   undefined   1      \"\"\n" + 
//			"   4   undefined   1      \"\"\n" + 
//			"   5   undefined   1      \"\"\n" + 
			"   6   word   2      \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 13 Alignment: 1", struct);
		//@formatter:on

		struct.insertBitFieldAt(2, 4, 6, IntegerDataType.dataType, 15, "bf3", "bf3Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
//			"   5   undefined   1      \"\"\n" + 
			"   6   word   2      \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 13 Alignment: 1", struct);
		//@formatter:on

		try {
			struct.insertBitFieldAt(2, 4, 21, IntegerDataType.dataType, 12, "bf4", "bf4Comment");
			fail(
				"expected - IllegalArgumentException: Bitfield does not fit within specified constraints");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		struct.insertBitFieldAt(2, 4, 21, IntegerDataType.dataType, 11, "bf4", "bf4Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
			"   4   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
			"   6   word   2      \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 13 Alignment: 1", struct);
		//@formatter:on

		struct.insertBitFieldAt(2, 4, 0, IntegerDataType.dataType, 0, "z", "zero bitfield");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
				"pack(disabled)\n" + 
				"Structure Test {\n" + 
				"   0   byte   1   field1   \"Comment1\"\n" + 
//				"   1   undefined   1      \"\"\n" + 
				"   2   int:0(0)   0      \"zero bitfield\"\n" + // field name discarded
				"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
				"   2   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
				"   2   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
				"   4   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
				"   6   word   2      \"Comment2\"\n" + 
				"   8   dword   4   field3   \"\"\n" + 
				"   12   byte   1   field4   \"Comment4\"\n" + 
				"}\n" + 
				"Length: 13 Alignment: 1", struct);
		//@formatter:on
	}

	@Test
	public void testInsertBitFieldAtBigEndian() throws Exception {

		transitionToBigEndian();

		try {
			struct.insertBitFieldAt(2, 4, 30, IntegerDataType.dataType, 3, "bf1", "bf1Comment");
			fail(
				"expected - IllegalArgumentException: Bitfield does not fit within specified constraints");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		struct.insertBitFieldAt(2, 4, 29, IntegerDataType.dataType, 3, "bf1", "bf1Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
			"   2   int:3(5)   1   bf1   \"bf1Comment\"\n" + 
//			"   3   undefined   1      \"\"\n" + 
//			"   4   undefined   1      \"\"\n" + 
//			"   5   undefined   1      \"\"\n" + 
			"   6   word   2      \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 13 Alignment: 1", struct);
		//@formatter:on

		struct.insertBitFieldAt(2, 4, 26, IntegerDataType.dataType, 3, "bf2", "bf2Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
			"   2   int:3(5)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(2)   1   bf2   \"bf2Comment\"\n" + 
//			"   3   undefined   1      \"\"\n" + 
//			"   4   undefined   1      \"\"\n" + 
//			"   5   undefined   1      \"\"\n" + 
			"   6   word   2      \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 13 Alignment: 1", struct);
		//@formatter:on

		struct.insertBitFieldAt(2, 4, 11, IntegerDataType.dataType, 15, "bf3", "bf3Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
			"   2   int:3(5)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(2)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(3)   3   bf3   \"bf3Comment\"\n" + 
//			"   5   undefined   1      \"\"\n" + 
			"   6   word   2      \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 13 Alignment: 1", struct);
		//@formatter:on

		struct.insertBitFieldAt(2, 4, 0, IntegerDataType.dataType, 11, "bf4", "bf4Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
			"   2   int:3(5)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(2)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(3)   3   bf3   \"bf3Comment\"\n" + 
			"   4   int:11(0)   2   bf4   \"bf4Comment\"\n" + 
			"   6   word   2      \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 13 Alignment: 1", struct);
		//@formatter:on

		struct.insertBitFieldAt(2, 4, 31, IntegerDataType.dataType, 0, "z", "zero bitfield");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" +  
			"   2   int:0(7)   0      \"zero bitfield\"\n" + // field name discarded
			"   2   int:3(5)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(2)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(3)   3   bf3   \"bf3Comment\"\n" + 
			"   4   int:11(0)   2   bf4   \"bf4Comment\"\n" + 
			"   6   word   2      \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 13 Alignment: 1", struct);
		//@formatter:on
	}

	@Test
	public void testInsertAtOffsetAfterBeforeBitField() throws Exception {

		// NOTE: little-endian packing applies

		struct.insertBitFieldAt(2, 4, 0, IntegerDataType.dataType, 3, "bf1", "bf1Comment");
		struct.insertBitFieldAt(2, 4, 3, IntegerDataType.dataType, 3, "bf2", "bf2Comment");
		struct.insertBitFieldAt(2, 4, 6, IntegerDataType.dataType, 15, "bf3", "bf3Comment");
		struct.insertBitFieldAt(2, 4, 21, IntegerDataType.dataType, 11, "bf4", "bf4Comment");

		struct.insertAtOffset(2, FloatDataType.dataType, 4);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
			"   2   float   4      \"\"\n" + 
			"   6   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   6   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
			"   6   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
			"   8   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
			"   10   word   2      \"Comment2\"\n" + 
			"   12   dword   4   field3   \"\"\n" + 
			"   16   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 17 Alignment: 1", struct);
		//@formatter:on

	}

	@Test
	public void testClearComponent() {
		struct.clearComponent(0);
		assertEquals(8, struct.getLength());
		assertEquals(4, struct.getNumComponents());
		DataTypeComponent dtc = struct.getComponent(0);
		assertEquals(DataType.DEFAULT, dtc.getDataType());
		dtc = struct.getComponent(1);
		assertEquals(WordDataType.class, dtc.getDataType().getClass());
	}

	@Test
	public void testClearComponent1() {
		struct.clearComponent(1);
		assertEquals(8, struct.getLength());
		assertEquals(5, struct.getNumComponents());
		DataTypeComponent dtc = struct.getComponent(1);
		assertEquals(DataType.DEFAULT, dtc.getDataType());
		dtc = struct.getComponent(2);
		assertEquals(DataType.DEFAULT, dtc.getDataType());
		dtc = struct.getComponent(0);
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());
		dtc = struct.getComponent(3);
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());
		assertEquals(3, dtc.getOrdinal());
		assertEquals(3, dtc.getOffset());
	}

	@Test
	public void testReplaceFailure() {// bigger, no space below
		DataTypeComponent dtc = null;
		try {
			dtc = struct.replace(0, new QWordDataType(), 8);
		}
		catch (IllegalArgumentException e) {
			// Not enough undefined bytes so should throw this.
		}
		assertNull(dtc);
	}

	@Test
	public void testReplace1() {// bigger, space below
		struct.insert(1, new QWordDataType());
		struct.clearComponent(1);
		assertEquals(16, struct.getLength());
		assertEquals(12, struct.getNumComponents());

		struct.replace(0, new QWordDataType(), 8);
		assertEquals(16, struct.getLength());
		assertEquals(5, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(9, comps[1].getOffset());
		assertEquals(2, comps[1].getOrdinal());
	}

	@Test
	public void testReplace2() {// same size
		struct.replace(0, new CharDataType(), 1);
		assertEquals(8, struct.getLength());
		assertEquals(4, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(CharDataType.class, comps[0].getDataType().getClass());
		assertEquals(1, comps[1].getOffset());
		assertEquals(1, comps[1].getOrdinal());
	}

	@Test
	public void testReplace3() {// smaller
		struct.replace(1, new CharDataType(), 1);
		assertEquals(8, struct.getLength());
		assertEquals(5, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(CharDataType.class, comps[1].getDataType().getClass());
		assertEquals(1, comps[1].getOffset());
		assertEquals(1, comps[1].getOrdinal());
		assertEquals(3, comps[2].getOffset());
		assertEquals(3, comps[2].getOrdinal());
		assertEquals(DWordDataType.class, comps[2].getDataType().getClass());
	}

	@Test
	public void testDataTypeReplaced1() {// bigger, space below
		Structure struct2 = createStructure("struct2", 3);
		Structure struct2A = createStructure("struct2A", 5);
		struct.insert(0, DataType.DEFAULT);
		struct.insert(3, struct2);
		struct.clearComponent(4);
		assertEquals(12, struct.getLength());
		assertEquals(9, struct.getNumComponents());

		struct.dataTypeReplaced(struct2, struct2A);
		assertEquals(12, struct.getLength());
		assertEquals(7, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(4, comps[2].getOffset());
		assertEquals(3, comps[2].getOrdinal());
		assertEquals(5, comps[2].getLength());
		assertEquals(11, comps[3].getOffset());
		assertEquals(6, comps[3].getOrdinal());

		// check that everything got properly written to the database by
		// forcing it to reload
		struct.setInvalid();

		comps = struct.getDefinedComponents();
		assertEquals(4, comps[2].getOffset());
		assertEquals(3, comps[2].getOrdinal());
		assertEquals(5, comps[2].getLength());
		assertEquals(11, comps[3].getOffset());
		assertEquals(6, comps[3].getOrdinal());

	}

	@Test
	public void testDataTypeReplaced3() {// bigger, no space at end (structure grows)
		Structure struct2 = createStructure("struct2", 3);
		Structure struct2A = createStructure("struct2A", 5);
		struct.add(struct2);
		assertEquals(11, struct.getLength());
		assertEquals(5, struct.getNumComponents());

		struct.dataTypeReplaced(struct2, struct2A);
		assertEquals(13, struct.getLength());
		assertEquals(5, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(8, comps[4].getOffset());
		assertEquals(4, comps[4].getOrdinal());
		assertEquals(5, comps[4].getLength());
	}

	@Test
	public void testDataTypeSizeChanged() {
		Structure struct2 = createStructure("struct2", 3);
		struct.add(struct2);
		assertEquals(11, struct.getLength());
		assertEquals(5, struct.getNumComponents());

		struct2.add(new WordDataType());
		assertEquals(13, struct.getLength());
		assertEquals(5, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(8, comps[4].getOffset());
		assertEquals(4, comps[4].getOrdinal());
		assertEquals(5, comps[4].getLength());
	}

	@Test
	public void testDataTypeComponentReplaced() {// bigger, no space at end (structure grows)
		Structure struct2 = createStructure("struct2", 3);
		Structure struct2A = createStructure("struct2A", 5);
		struct.add(struct2);
		assertEquals(11, struct.getLength());
		assertEquals(5, struct.getNumComponents());

		struct.replace(4, struct2A, struct2A.getLength());
		assertEquals(13, struct.getLength());
		assertEquals(5, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(8, comps[4].getOffset());
		assertEquals(4, comps[4].getOrdinal());
		assertEquals(5, comps[4].getLength());
	}

	@Test
	public void testDataTypeReplaced2() {// smaller, create undefineds
		Structure struct2 = createStructure("struct2", 5);
		Structure struct2A = createStructure("struct2A", 3);
		struct.insert(0, DataType.DEFAULT);
		struct.insert(0, DataType.DEFAULT);
		struct.insert(4, struct2);
		assertEquals(15, struct.getLength());
		assertEquals(7, struct.getNumComponents());

		struct.dataTypeReplaced(struct2, struct2A);

		assertEquals(15, struct.getLength());
		assertEquals(9, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(5, comps[2].getOffset());
		assertEquals(4, comps[2].getOrdinal());
		assertEquals(3, comps[2].getLength());
		assertEquals(10, comps[3].getOffset());
		assertEquals(7, comps[3].getOrdinal());
	}

	@Test
	public void testDeleteFlexArrayDependency() {

		assertEquals(4, struct.getNumComponents());
		assertEquals(8, struct.getLength());

		struct.add(new ArrayDataType(IntegerDataType.dataType, 0, -1), "flex", "FlexComment");
		assertEquals(5, struct.getNumComponents());
		assertEquals(8, struct.getLength());

		dataMgr.remove(dataMgr.resolve(IntegerDataType.dataType, null), TaskMonitor.DUMMY);

		assertEquals(4, struct.getNumComponents());
		assertEquals(8, struct.getLength());
	}

	@Test
	public void testDeleteBitFieldDependency() throws InvalidDataTypeException {

		TypeDef td = new TypedefDataType("Foo", IntegerDataType.dataType);
		td = (TypeDef) dataMgr.resolve(td, null);

		struct.addBitField(td, 4, "MyBit1", "bitComment");
		struct.addBitField(td, 3, "MyBit2", "bitComment");
		struct.addBitField(td, 2, "MyBit3", "bitComment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2      \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
			"   8   Foo:4(0)   1   MyBit1   \"bitComment\"\n" + 
			"   9   Foo:3(0)   1   MyBit2   \"bitComment\"\n" + 
			"   10   Foo:2(0)   1   MyBit3   \"bitComment\"\n" + 
			"}\n" + 
			"Length: 11 Alignment: 1", struct);
		//@formatter:on

		dataMgr.remove(td, TaskMonitor.DUMMY);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2      \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
//			"   8   undefined   1      \"\"\n" + 
//			"   9   undefined   1      \"\"\n" + 
//			"   10   undefined   1      \"\"\n" + 
			"}\n" + 
			"Length: 11 Alignment: 1", struct);
		//@formatter:on
	}

	@Test
	public void testReplaceFlexArrayDependency() throws DataTypeDependencyException {

		struct.setPackingEnabled(true);

		struct.delete(2); // remove dword to verify flex array alignment below

		TypeDef td = new TypedefDataType("Foo", IntegerDataType.dataType);
		td = (TypeDef) dataMgr.resolve(td, null);

		DataTypeComponent flexDtc = struct.add(new ArrayDataType(td, 0, -1), "flex", "FlexComment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack()\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   2   word   2      \"Comment2\"\n" + 
			"   4   byte   1   field4   \"Comment4\"\n" + 
			"   8   Foo[0]   0   flex   \"FlexComment\"\n" + 
			"}\n" + 
			"Length: 8 Alignment: 4", struct);
		//@formatter:on

		dataMgr.replaceDataType(td, ByteDataType.dataType, false);

		flexDtc = struct.getComponent(flexDtc.getOrdinal());
		assertNotNull(flexDtc);

		// FIXME: repack was not triggered with replacement

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack()\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   2   word   2      \"Comment2\"\n" + 
			"   4   byte   1   field4   \"Comment4\"\n" + 
			"   5   byte[0]   0   flex   \"FlexComment\"\n" + 
			"}\n" + 
			"Length: 6 Alignment: 2", struct);
		//@formatter:on
	}

	@Test
	public void testReplaceBitFieldDependency()
			throws InvalidDataTypeException, DataTypeDependencyException {

		struct.setPackingEnabled(true);

		TypeDef td = new TypedefDataType("Foo", IntegerDataType.dataType);
		td = (TypeDef) dataMgr.resolve(td, null);

		struct.addBitField(td, 4, "MyBit1", "bitComment1");
		struct.addBitField(td, 3, "MyBit2", "bitComment2");
		struct.addBitField(td, 2, "MyBit3", "bitComment3");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack()\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   2   word   2      \"Comment2\"\n" + 
			"   4   dword   4   field3   \"\"\n" + 
			"   8   byte   1   field4   \"Comment4\"\n" + 
			"   9   Foo:4(0)   1   MyBit1   \"bitComment1\"\n" + 
			"   9   Foo:3(4)   1   MyBit2   \"bitComment2\"\n" + 
			"   9   Foo:2(7)   2   MyBit3   \"bitComment3\"\n" + 
			"}\n" + 
			"Length: 12 Alignment: 4", struct);
		//@formatter:on

		dataMgr.replaceDataType(td, CharDataType.dataType, false);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack()\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   2   word   2      \"Comment2\"\n" + 
			"   4   dword   4   field3   \"\"\n" + 
			"   8   byte   1   field4   \"Comment4\"\n" + 
			"   9   char:4(0)   1   MyBit1   \"bitComment1\"\n" + 
			"   9   char:3(4)   1   MyBit2   \"bitComment2\"\n" + 
			"   10   char:2(0)   1   MyBit3   \"bitComment3\"\n" + 
			"}\n" + 
			"Length: 12 Alignment: 4", struct);
		//@formatter:on
	}

	@Test
	public void testReplaceWith() {
		assertEquals(8, struct.getLength());
		assertEquals(4, struct.getNumComponents());

		Structure newStruct = createStructure("Replaced", 8);
		newStruct.setDescription("testReplaceWith()");
		DataTypeComponent dtc0 = newStruct.insert(2, new ByteDataType(), 1, "field3", "Comment1");
		DataTypeComponent dtc1 = newStruct.insert(5, new WordDataType(), 2, null, "Comment2");
		DataTypeComponent dtc2 = newStruct.insert(7, new DWordDataType(), 4, "field8", null);

		struct.replaceWith(newStruct);
		assertEquals(15, struct.getLength());
		assertEquals(11, struct.getNumComponents());
		DataTypeComponent[] dtcs = struct.getDefinedComponents();
		assertEquals(3, dtcs.length);
		assertEquals(dtc0, dtcs[0]);
		assertEquals(dtc1, dtcs[1]);
		assertEquals(dtc2, dtcs[2]);
		assertEquals("Test", struct.getName());
		assertEquals("testReplaceWith()", struct.getDescription());
	}

	@Test
	public void testReplaceWith2() throws InvalidDataTypeException {

		// NOTE: non-packed bitfields should remain unchanged when
		// transitioning endianness even though it makes little sense.
		// Unaligned structures are not intended to be portable! 

		TypeDef td = new TypedefDataType("Foo", IntegerDataType.dataType);
		td = (TypeDef) dataMgr.resolve(td, null);

		struct.insertBitFieldAt(9, 1, 0, td, 4, "MyBit1", "bitComment1");
		struct.insertBitFieldAt(9, 1, 4, td, 3, "MyBit2", "bitComment2");
		struct.insertBitFieldAt(9, 2, 7, td, 2, "MyBit3", "bitComment3");
		struct.growStructure(1);

		struct.add(new ArrayDataType(td, 0, -1), "myFlex", "flexComment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2      \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
//			"   8   undefined   1      \"\"\n" + 
			"   9   Foo:4(0)   1   MyBit1   \"bitComment1\"\n" + 
			"   9   Foo:3(4)   1   MyBit2   \"bitComment2\"\n" + 
			"   9   Foo:2(7)   2   MyBit3   \"bitComment3\"\n" + 
//			"   11   undefined   1      \"\"\n" + 
			"   12   Foo[0]   0   myFlex   \"flexComment\"\n" + 
			"}\n" + 
			"Length: 12 Alignment: 1", struct);
		//@formatter:on

		transitionToBigEndian();

		Structure newStruct =
			(Structure) dataMgr.resolve(new StructureDataType("bigStruct", 0), null);
		newStruct.replaceWith(struct);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/bigStruct\n" + 
			"pack(disabled)\n" + 
			"Structure bigStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2      \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
//			"   8   undefined   1      \"\"\n" + 
			"   9   Foo:4(0)   1   MyBit1   \"bitComment1\"\n" + 
			"   9   Foo:3(4)   1   MyBit2   \"bitComment2\"\n" + 
			"   9   Foo:2(7)   2   MyBit3   \"bitComment3\"\n" + 
//			"   11   undefined   1      \"\"\n" + 
			"   12   Foo[0]   0   myFlex   \"flexComment\"\n" + 
			"}\n" + 
			"Length: 12 Alignment: 1", newStruct);
		//@formatter:on
	}

	@Test
	public void testReplaceWithConflict() {

		// Test case where structure BAR contains a not-yet-defined structure FOO (impl)
		// which has previously been resolved as fully defined.  Test verifies that resolving
		// BAR properly handles the conflict replacement of the FOO component with a larger
		// fully defined datatype.

		Structure fooNotYetDefined = new StructureDataType("FOO", 0);

		Structure fooDefined = new StructureDataType("FOO", 0);
		fooDefined.add(new ArrayDataType(ByteDataType.dataType, 20, 1));
		fooDefined = (Structure) dataMgr.resolve(fooDefined, null);

		Structure barStruct = new StructureDataType("BAR", 40);
		barStruct.replaceAtOffset(0, fooNotYetDefined, -1, "f1", null);
		barStruct.replaceAtOffset(10, ByteDataType.dataType, 1, "f2", null);

		barStruct = (Structure) dataMgr.resolve(barStruct,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/BAR\n" + 
			"pack(disabled)\n" + 
			"Structure BAR {\n" + 
			"   0   FOO   10   f1   \"\"\n" + 
			"   10   byte   1   f2   \"\"\n" + 
			"}\n" + 
			"Length: 40 Alignment: 1", barStruct);
		//@formatter:on

		DataTypeComponent dtc1 = barStruct.getDefinedComponents()[1];
		assertEquals(1, dtc1.getOrdinal());
		assertEquals(dtc1, barStruct.getComponent(1));
	}

	@Test
	public void testReplaceWithConflict2() {

		// Test case where structure BAR contains a not-yet-defined structure FOO (impl)
		// which has previously been resolved as fully defined.  Test verifies that resolving
		// BAR properly handles the conflict replacement of the FOO component with a larger
		// fully defined datatype.

		Structure fooNotYetDefined = new StructureDataType("FOO", 0);

		Structure fooDefined = new StructureDataType("FOO", 0);
		fooDefined.add(new ArrayDataType(ByteDataType.dataType, 5, 1));
		fooDefined = (Structure) dataMgr.resolve(fooDefined, null);

		Structure barStruct = new StructureDataType("BAR", 40);
		barStruct.replaceAtOffset(0, fooNotYetDefined, -1, "f1", null);
		barStruct.replaceAtOffset(10, ByteDataType.dataType, 1, "f2", null);

		barStruct = (Structure) dataMgr.resolve(barStruct,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/BAR\n" + 
			"pack(disabled)\n" + 
			"Structure BAR {\n" + 
			"   0   FOO   5   f1   \"\"\n" + 
			"   10   byte   1   f2   \"\"\n" + 
			"}\n" + 
			"Length: 40 Alignment: 1", barStruct);
		//@formatter:on

		DataTypeComponent dtc1 = barStruct.getDefinedComponents()[1];
		assertEquals(6, dtc1.getOrdinal());
		assertEquals(dtc1, barStruct.getComponent(6));

	}
	
	@Test
	public void testSetLength() {

		assertEquals(8, struct.getLength());
		assertEquals(4, struct.getNumComponents());
		assertEquals(4, struct.getNumDefinedComponents());
		
		struct.setLength(20);
		assertEquals(20, struct.getLength());
		assertEquals(16, struct.getNumComponents());
		assertEquals(4, struct.getNumDefinedComponents());
		
		// new length is offcut within 3rd component at offset 0x3 which should get cleared
		struct.setLength(4);
		assertEquals(4, struct.getLength());
		assertEquals(3, struct.getNumComponents());
		assertEquals(2, struct.getNumDefinedComponents());
		
		// Maximum length supported by GUI editor is ~Integer.MAX_VALUE/10
		int len = Integer.MAX_VALUE / 10;
		struct.setLength(len);
		assertEquals(len, struct.getLength());
		assertEquals(len - 1, struct.getNumComponents());
		assertEquals(2, struct.getNumDefinedComponents());
		
		len /= 2;
		struct.replaceAtOffset(len-2, WordDataType.dataType, -1, "x", null); // will be preserved below
		struct.replaceAtOffset(len+2, WordDataType.dataType, -1, "y", null); // will be cleared below
		struct.setLength(len);
		assertEquals(len, struct.getLength());
		assertEquals(len - 2, struct.getNumComponents());
		assertEquals(3, struct.getNumDefinedComponents());
	}

	@Test
	public void testDeleteMany() {

		struct.growStructure(20);
		struct.insertAtOffset(12, WordDataType.dataType, -1, "A", null);
		struct.insertAtOffset(16, WordDataType.dataType, -1, "B", null);

		assertEquals(32, struct.getLength());
		assertEquals(26, struct.getNumComponents());
		assertEquals(6, struct.getNumDefinedComponents());

		struct.delete(Sets.newHashSet(1, 4, 5));

		assertEquals(28, struct.getLength());
		assertEquals(23, struct.getNumComponents());
		assertEquals(5, struct.getNumDefinedComponents());

		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(WordDataType.class, comps[3].getDataType().getClass());
		assertEquals(5, comps[3].getOrdinal());
		assertEquals(8, comps[3].getOffset());

		// Verify that records were properly updated by comitting and performing an undo/redo
		dataMgr.endTransaction(txId, true);
		dataMgr.undo();
		dataMgr.redo();
		txId = dataMgr.startTransaction("Continue Test");

		assertEquals(28, struct.getLength());
		assertEquals(23, struct.getNumComponents());
		assertEquals(5, struct.getNumDefinedComponents());

		comps = struct.getDefinedComponents();
		assertEquals(WordDataType.class, comps[3].getDataType().getClass());
		assertEquals(5, comps[3].getOrdinal());
		assertEquals(8, comps[3].getOffset());
	}

	@Test
	public void testDeleteManyBF() throws InvalidDataTypeException {

		struct.insertBitFieldAt(2, 4, 0, IntegerDataType.dataType, 3, "bf1", "bf1Comment");
		struct.insertBitFieldAt(2, 4, 3, IntegerDataType.dataType, 3, "bf2", "bf2Comment");
		struct.insertBitFieldAt(2, 4, 6, IntegerDataType.dataType, 15, "bf3", "bf3Comment");
		struct.insertBitFieldAt(2, 4, 21, IntegerDataType.dataType, 11, "bf4", "bf4Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//					"   1   undefined   1      \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
			"   4   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
			"   6   word   2      \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 13 Alignment: 1", struct);
		//@formatter:on

		struct.delete(Sets.newHashSet(1, 2, 3, 4, 5, 6));

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//					"   1   undefined   1      \"\"\n" + 
//					"   2   undefined   1      \"\"\n" + 
//					"   3   undefined   1      \"\"\n" + 
//					"   4   undefined   1      \"\"\n" + 
			"   5   dword   4   field3   \"\"\n" + 
			"   9   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 10 Alignment: 1", struct);
		//@formatter:on

		assertEquals(10, struct.getLength());
		assertEquals(7, struct.getNumComponents());
		assertEquals(3, struct.getNumDefinedComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(DWordDataType.class, comps[1].getDataType().getClass());
		assertEquals(5, comps[1].getOffset());
	}

	@Test
	public void testDelete() throws InvalidDataTypeException {

		struct.insertBitFieldAt(2, 4, 0, IntegerDataType.dataType, 3, "bf1", "bf1Comment");
		struct.insertBitFieldAt(2, 4, 3, IntegerDataType.dataType, 3, "bf2", "bf2Comment");
		struct.insertBitFieldAt(2, 4, 6, IntegerDataType.dataType, 15, "bf3", "bf3Comment");
		struct.insertBitFieldAt(2, 4, 21, IntegerDataType.dataType, 11, "bf4", "bf4Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
			"   4   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
			"   6   word   2      \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 13 Alignment: 1", struct);
		//@formatter:on

		struct.delete(6);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
			"   4   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
			"   6   dword   4   field3   \"\"\n" + 
			"   10   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 11 Alignment: 1", struct);
		//@formatter:on

		struct.delete(3);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
			"   4   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
			"   6   dword   4   field3   \"\"\n" + 
			"   10   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 11 Alignment: 1", struct);
		//@formatter:on

		struct.delete(3);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
//			"   3   undefined   1      \"\"\n" + 
			"   4   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
			"   6   dword   4   field3   \"\"\n" + 
			"   10   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 11 Alignment: 1", struct);
		//@formatter:on

		struct.delete(4);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
//			"   3   undefined   1      \"\"\n" + 
//			"   4   undefined   1      \"\"\n" + 
//			"   5   undefined   1      \"\"\n" + 
			"   6   dword   4   field3   \"\"\n" + 
			"   10   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 11 Alignment: 1", struct);
		//@formatter:on

		struct.delete(2);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
//			"   2   undefined   1      \"\"\n" + 
//			"   3   undefined   1      \"\"\n" + 
//			"   4   undefined   1      \"\"\n" + 
//			"   5   undefined   1      \"\"\n" + 
			"   6   dword   4   field3   \"\"\n" + 
			"   10   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 11 Alignment: 1", struct);
		//@formatter:on

		struct.delete(2);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/Test\n" + 
			"pack(disabled)\n" + 
			"Structure Test {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1      \"\"\n" + 
//			"   2   undefined   1      \"\"\n" + 
//			"   3   undefined   1      \"\"\n" + 
//			"   4   undefined   1      \"\"\n" + 
			"   5   dword   4   field3   \"\"\n" + 
			"   9   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Length: 10 Alignment: 1", struct);
		//@formatter:on

		assertEquals(10, struct.getLength());
		assertEquals(7, struct.getNumComponents());
		assertEquals(3, struct.getNumDefinedComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(DWordDataType.class, comps[1].getDataType().getClass());
		assertEquals(5, comps[1].getOffset());
	}

	@Test
	public void testClearAtOffset() {

		assertEquals(8, struct.getLength());

		Array zeroArray = new ArrayDataType(CharDataType.dataType, 0, -1);
		struct.insertAtOffset(1, zeroArray, -1);

		assertEquals(8, struct.getLength());

		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(5, comps.length);

		assertEquals(0, comps[0].getOffset());
		assertEquals(0, comps[0].getOrdinal());
		assertEquals(ByteDataType.class, comps[0].getDataType().getClass());

		assertEquals(1, comps[1].getOffset());
		assertEquals(1, comps[1].getOrdinal());
		assertTrue(zeroArray.isEquivalent(comps[1].getDataType()));

		assertEquals(1, comps[2].getOffset());
		assertEquals(2, comps[2].getOrdinal());
		assertEquals(WordDataType.class, comps[2].getDataType().getClass());

		assertEquals(3, comps[3].getOffset());
		assertEquals(3, comps[3].getOrdinal());
		assertEquals(DWordDataType.class, comps[3].getDataType().getClass());

		struct.clearAtOffset(1);

		assertEquals(8, struct.getLength());
		assertEquals(5, struct.getNumComponents()); // 2 undefined components replaced word
		comps = struct.getDefinedComponents();

		assertEquals(DWordDataType.class, comps[1].getDataType().getClass());
		assertEquals(3, comps[1].getOffset());
		assertEquals(3, comps[1].getOrdinal());
	}

	@Test
	public void testDeleteAtOffset() {
		struct.deleteAtOffset(2);
		assertEquals(6, struct.getLength());
		assertEquals(3, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(DWordDataType.class, comps[1].getDataType().getClass());
		assertEquals(1, comps[1].getOffset());
	}

	@Test
	public void testDeleteAtOffset2() {

		assertEquals(8, struct.getLength());

		Array zeroArray = new ArrayDataType(CharDataType.dataType, 0, -1);
		struct.insertAtOffset(1, zeroArray, -1);

		assertEquals(8, struct.getLength());

		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(5, comps.length);

		assertEquals(0, comps[0].getOffset());
		assertEquals(0, comps[0].getOrdinal());
		assertEquals(ByteDataType.class, comps[0].getDataType().getClass());

		assertEquals(1, comps[1].getOffset());
		assertEquals(1, comps[1].getOrdinal());
		assertTrue(zeroArray.isEquivalent(comps[1].getDataType()));

		assertEquals(1, comps[2].getOffset());
		assertEquals(2, comps[2].getOrdinal());
		assertEquals(WordDataType.class, comps[2].getDataType().getClass());

		struct.deleteAtOffset(1);

		assertEquals(6, struct.getLength());
		assertEquals(3, struct.getNumComponents());
		comps = struct.getDefinedComponents();

		assertEquals(DWordDataType.class, comps[1].getDataType().getClass());
		assertEquals(1, comps[1].getOffset());
	}

	@Test
	public void testDeleteComponent() {
		Structure s = new StructureDataType("test1", 0);
		s.add(new ByteDataType());
		s.add(new FloatDataType());

		struct.add(s);

		DataType dt = struct.getDataTypeManager().getDataType(struct.getCategoryPath(), "test1");
		assertNotNull(dt);

		DataTypeComponent[] dtc = struct.getComponents();
		assertEquals(5, dtc.length);

		dt.getDataTypeManager().remove(dt, new TaskMonitorAdapter());
		dtc = struct.getComponents();
		assertEquals(9, dtc.length);

		assertEquals(9, struct.getNumComponents());
	}

	@Test
	public void testDeleteAll() {

		Structure s = new StructureDataType("test1", 0);
		s.add(new ByteDataType());
		s.add(new FloatDataType());

		struct.add(s);

		DataType dt = struct.getDataTypeManager().getDataType(struct.getCategoryPath(), "test1");
		s = (Structure) dt;
		s.deleteAll();
		assertEquals(1, s.getLength());
		assertTrue(s.isNotYetDefined());
		assertTrue(s.isZeroLength());
		assertEquals(0, s.getNumComponents());
	}

	@Test
	public void testGetComponentAt() {
		/**
		* /TestStruct
		* pack(disabled)
		* Structure TestStruct {
		*    0   byte   1   field1   "Comment1"
		*    1   word   2      "Comment2"
		*    3   dword   4   field3   ""
		*    7   byte   1   field4   "Comment4"
		* }
		* Length: 8 Alignment: 1
		*/

		DataTypeComponent dtc = struct.getComponentAt(3);
		assertEquals("  2  3  dword  4  field3  ", dtc.toString());

		dtc = struct.getComponentAt(4); // offcut
		assertNull(dtc);

		assertEquals(8, struct.getLength());

		dtc = struct.getComponentAt(8);
		assertNull(dtc);

		struct.add(new ArrayDataType(CharDataType.dataType, 0, -1), "zarray1", null);
		struct.add(new LongDataType(), "field4", null);
		struct.add(new ArrayDataType(LongDataType.dataType, 0, -1), "zarray2", null);

		assertEquals(12, struct.getLength());

		/**
		* /TestStruct
		* pack(disabled)
		* Structure TestStruct {
		*    0   byte   1   field1   "Comment1"
		*    1   word   2      "Comment2"
		*    3   dword   4   field3   ""
		*    7   byte   1   field4   "Comment4"
		*    8   char[0]   0   zarray1   ""
		*    8   long   4   field4   ""
		*    12   long[0]   0   zarray2   ""
		* }
		* Length: 12 Alignment: 1
		*/

		dtc = struct.getComponentAt(8);
		assertEquals("  5  8  long  4  field4  ", dtc.toString());

		dtc = struct.getComponentAt(9); // offcut
		assertNull(dtc);

		dtc = struct.getComponentAt(12); // end-of-struct
		assertNull(dtc);

		// force components to align
		struct.setPackingEnabled(true);

		/**
		 * /Test
		 * pack(disabled)
		 * Structure Test {
		 *    0   byte   1   field1   "Comment1"
		 *    2   word   2      "Comment2"
		 *    4   dword   4   field3   ""
		 *    8   byte   1   field4   "Comment4"
		 *    9   char[0]   0   zarray1   ""
		 *    12   long   4   field4   ""
		 *    16   long[0]   0   zarray2   ""
		 * }
		 * Length: 16 Alignment: 1
		 */

		assertEquals(16, struct.getLength());

		dtc = struct.getComponentAt(9); // offset of zero-length component
		assertNull(dtc);

		struct.setPackingEnabled(false);

		dtc = struct.getComponentAt(9); // undefined at offset of zero-length component
		assertEquals("  5  9  undefined  1    ", dtc.toString());

	}

	@Test
	public void testGetComponentContaining() {
		DataTypeComponent dtc = struct.getComponentContaining(4);
		assertEquals("  2  3  dword  4  field3  ", dtc.toString());

		assertEquals(8, struct.getLength());

		dtc = struct.getComponentContaining(8);
		assertNull(dtc);

		struct.add(new ArrayDataType(CharDataType.dataType, 0, -1), "zarray1", null);
		struct.add(new LongDataType(), "field4", null);
		struct.add(new ArrayDataType(LongDataType.dataType, 0, -1), "zarray2", null);

		assertEquals(12, struct.getLength());

		/**
		* /TestStruct
		* pack(disabled)
		* Structure TestStruct {
		*    0   byte   1   field1   "Comment1"
		*    1   word   2      "Comment2"
		*    3   dword   4   field3   ""
		*    7   byte   1   field4   "Comment4"
		*    8   char[0]   0   zarray1   ""
		*    8   long   4   field4   ""
		*    12   long[0]   0   zarray2   ""
		* }
		* Length: 12 Alignment: 1
		*/

		dtc = struct.getComponentContaining(8);
		assertEquals("  5  8  long  4  field4  ", dtc.toString());

		dtc = struct.getComponentContaining(9); // offcut
		assertEquals("  5  8  long  4  field4  ", dtc.toString());

		dtc = struct.getComponentContaining(12); // end-of-struct
		assertNull(dtc);

		// force components to align
		struct.setPackingEnabled(true);

		/**
		 * /Test
		 * pack(disabled)
		 * Structure Test {
		 *    0   byte   1   field1   "Comment1"
		 *    2   word   2      "Comment2"
		 *    4   dword   4   field3   ""
		 *    8   byte   1   field4   "Comment4"
		 *    9   char[0]   0   zarray1   ""
		 *    12   long   4   field4   ""
		 *    16   long[0]   0   zarray2   ""
		 * }
		 * Length: 16 Alignment: 1
		 */

		assertEquals(16, struct.getLength());

		dtc = struct.getComponentContaining(9); // offset of zero-length component
		assertNull(dtc);

		struct.setPackingEnabled(false);

		dtc = struct.getComponentContaining(9); // undefined at offset of zero-length component
		assertEquals("  5  9  undefined  1    ", dtc.toString());

	}

	@Test
	public void testGetComponentsContaining() {
		List<DataTypeComponent> components = struct.getComponentsContaining(4);
		assertEquals("[  2  3  dword  4  field3  ]", components.toString());

		struct.add(new ArrayDataType(CharDataType.dataType, 0, -1), "zarray1", null);
		struct.add(new LongDataType(), "field4", null);
		struct.add(new ArrayDataType(LongDataType.dataType, 0, -1), "zarray2", null);

		// force components to align
		struct.setPackingEnabled(true);
		struct.setPackingEnabled(false);

		assertEquals(16, struct.getLength());

		/**
		 * /Test
		 * pack(disabled)
		 * Structure Test {
		 *    0   byte   1   field1   "Comment1"
		 *    2   word   2      "Comment2"
		 *    4   dword   4   field3   ""
		 *    8   byte   1   field4   "Comment4"
		 *    9   char[0]   0   zarray1   ""
		 *    12   long   4   field4   ""
		 *    16   long[0]   0   zarray2   ""
		 * }
		 * Length: 16 Alignment: 1
		 */

		// DatatypeComponent.toString: <ordinal> <offset> <dtname> <length> <fieldname> <comment>
		components = struct.getComponentsContaining(9);
		assertEquals("[  5  9  char[0]  0  zarray1  ,   6  9  undefined  1    ]",
			components.toString());

		components = struct.getComponentsContaining(10);
		assertEquals("[  7  10  undefined  1    ]", components.toString());

		components = struct.getComponentsContaining(16);
		assertEquals("[  10  16  long[0]  0  zarray2  ]", components.toString());

	}

	@Test
	public void testGetDataTypeAt() {
		Structure s1 = createStructure("Test1", 0);
		s1.add(new WordDataType());
		s1.add(struct);
		s1.add(new ByteDataType());

		DataTypeComponent dtc = s1.getComponentContaining(7);
		assertEquals(struct, dtc.getDataType());
		dtc = s1.getDataTypeAt(7);
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());
	}

	@Test
	public void testAddVarLengthDataTypes() {
		Structure s1 = createStructure("Test1", 0);
		s1.add(new StringDataType(), 5);
		s1.add(new StringDataType(), 10);
		s1.add(new StringDataType(), 15);

		DataTypeComponent dtc = s1.getComponentContaining(5);
		DataType dt = dtc.getDataType();
		assertEquals(-1, dt.getLength());
		assertEquals(10, dtc.getLength());
		assertEquals("string", dt.getDisplayName());

	}

	@Test
	public void testReplaceAtVarLengthDataTypes() {

		// TODO: these tests are too simple since they only replace undefined components

		Structure s1 = new StructureDataType("Test1", 25);

		s1.replaceAtOffset(0, new StringDataType(), 5, null, null);
		s1.replaceAtOffset(5, new StringDataType(), 10, null, null);
		s1.replaceAtOffset(15, new StringDataType(), 10, null, null);

		dataMgr.getRootCategory();
		s1 = (Structure) dataMgr.resolve(s1, null);

		DataTypeComponent dtc = s1.getComponentContaining(5);
		DataType dt = dtc.getDataType();
		assertEquals(-1, dt.getLength());
		assertEquals(10, dtc.getLength());
		assertEquals("string", dt.getDisplayName());
	}

	@Test
	public void testReplaceAtVarLengthDataTypes2() {

		// TODO: these tests are too simple since they only replace undefined components

		Structure s1 = new StructureDataType("Test1", 0x60);
		s1.replaceAtOffset(0, new StringDataType(), 0xd, null, null);

		s1.replaceAtOffset(0xd, new StringDataType(), 0xd, null, null);
		s1.replaceAtOffset(0x19, new StringDataType(), 0xc, null, null);
		s1.replaceAtOffset(0x24, new StringDataType(), 0xb, null, null);
		s1.replaceAtOffset(0x31, new StringDataType(), 0xd, null, null);
		s1.replaceAtOffset(0x3e, new StringDataType(), 0xa, null, null);
		s1.replaceAtOffset(0x48, new StringDataType(), 0xb, null, null);
		s1.replaceAtOffset(0x53, new StringDataType(), 0xd, null, null);

		dataMgr.getRootCategory();
		s1 = (Structure) dataMgr.resolve(s1, null);

		DataTypeComponent dtc = s1.getComponentContaining(0);
		DataType dt = dtc.getDataType();
		assertEquals("string", dt.getDisplayName());
		assertEquals(0xd, dtc.getLength());

		dtc = s1.getComponentContaining(0x31);
		dt = dtc.getDataType();
		assertEquals("string", dt.getDisplayName());
		assertEquals(0xd, dtc.getLength());
	}

	@Test
	public void testReplaceAtPacked() {

		struct.setPackingEnabled(true); // test case where there is no component

		assertEquals(12, struct.getLength());
		assertEquals(4, struct.getNumDefinedComponents());

		struct.replaceAtOffset(0, DataType.DEFAULT, -1, "a", null);
		struct.replaceAtOffset(1, ByteDataType.dataType, -1, "b", null);
		struct.replaceAtOffset(2, ByteDataType.dataType, -1, "c", null);

		assertEquals(12, struct.getLength());
		assertEquals(5, struct.getNumDefinedComponents());

		DataTypeComponent[] comps = struct.getDefinedComponents();

		assertEquals(0, comps[0].getOffset());
		assertEquals(0, comps[0].getOrdinal());
		assertTrue(Undefined1DataType.dataType.isEquivalent(comps[0].getDataType()));

		assertEquals(1, comps[1].getOffset());
		assertEquals(1, comps[1].getOrdinal());
		assertTrue(ByteDataType.dataType.isEquivalent(comps[1].getDataType()));

		assertEquals(2, comps[2].getOffset());
		assertEquals(2, comps[2].getOrdinal());
		assertTrue(ByteDataType.dataType.isEquivalent(comps[2].getDataType()));

		assertEquals(4, comps[3].getOffset());
		assertEquals(3, comps[3].getOrdinal());
		assertTrue(DWordDataType.dataType.isEquivalent(comps[3].getDataType()));

		assertEquals(8, comps[4].getOffset());
		assertEquals(4, comps[4].getOrdinal());
		assertTrue(ByteDataType.dataType.isEquivalent(comps[4].getDataType()));

	}

	@Test
	public void testReplaceAt() {

		assertEquals(8, struct.getLength());
		assertEquals(4, struct.getNumDefinedComponents());

		struct.replaceAtOffset(0, DataType.DEFAULT, -1, "a", null);
		struct.replaceAtOffset(1, ByteDataType.dataType, -1, "b", null);
		struct.replaceAtOffset(2, ByteDataType.dataType, -1, "c", null);
		struct.replaceAtOffset(4, CharDataType.dataType, -1, "d", null);

		assertEquals(8, struct.getLength());
		assertEquals(4, struct.getNumDefinedComponents());

		DataTypeComponent[] comps = struct.getDefinedComponents();

		assertEquals(1, comps[0].getOffset());
		assertEquals(1, comps[0].getOrdinal());
		assertTrue(ByteDataType.dataType.isEquivalent(comps[0].getDataType()));

		assertEquals(2, comps[1].getOffset());
		assertEquals(2, comps[1].getOrdinal());
		assertTrue(ByteDataType.dataType.isEquivalent(comps[1].getDataType()));

		assertEquals(4, comps[2].getOffset());
		assertEquals(4, comps[2].getOrdinal());
		assertTrue(CharDataType.dataType.isEquivalent(comps[2].getDataType()));

		assertEquals(7, comps[3].getOffset());
		assertEquals(7, comps[3].getOrdinal());
		assertTrue(ByteDataType.dataType.isEquivalent(comps[3].getDataType()));

	}

	@Test
	public void testReplaceAtWithZeroLength() {
		Array zeroArray = new ArrayDataType(FloatDataType.dataType, 0, -1);
		struct.insertAtOffset(3, zeroArray, -1);
		assertEquals(8, struct.getLength());
		assertEquals(5, struct.getNumDefinedComponents());

		// replace dword with short
		struct.replaceAtOffset(3, ShortDataType.dataType, -1, "b", null);

		assertEquals(8, struct.getLength());
		assertEquals(5, struct.getNumDefinedComponents());

		DataTypeComponent[] comps = struct.getDefinedComponents();

		assertEquals(0, comps[0].getOffset());
		assertEquals(0, comps[0].getOrdinal());
		assertTrue(ByteDataType.dataType.isEquivalent(comps[0].getDataType()));

		assertEquals(1, comps[1].getOffset());
		assertEquals(1, comps[1].getOrdinal());
		assertTrue(WordDataType.dataType.isEquivalent(comps[1].getDataType()));

		assertEquals(3, comps[2].getOffset());
		assertEquals(2, comps[2].getOrdinal());
		assertTrue(zeroArray.isEquivalent(comps[2].getDataType()));

		assertEquals(3, comps[3].getOffset());
		assertEquals(3, comps[3].getOrdinal());
		assertTrue(ShortDataType.dataType.isEquivalent(comps[3].getDataType()));

		assertEquals(7, comps[4].getOffset());
		assertEquals(6, comps[4].getOrdinal());
		assertTrue(ByteDataType.dataType.isEquivalent(comps[4].getDataType()));

		Array zeroArray2 = new ArrayDataType(CharDataType.dataType, 0, -1);

		// replace float[0] with char[0]
		struct.replaceAtOffset(3, zeroArray2, -1, "a", null);

		comps = struct.getDefinedComponents();

		assertEquals(0, comps[0].getOffset());
		assertEquals(0, comps[0].getOrdinal());
		assertTrue(ByteDataType.dataType.isEquivalent(comps[0].getDataType()));

		assertEquals(1, comps[1].getOffset());
		assertEquals(1, comps[1].getOrdinal());
		assertTrue(WordDataType.dataType.isEquivalent(comps[1].getDataType()));

		assertEquals(3, comps[2].getOffset());
		assertEquals(2, comps[2].getOrdinal());
		assertTrue(zeroArray.isEquivalent(comps[2].getDataType()));

		assertEquals(3, comps[3].getOffset());
		assertEquals(3, comps[3].getOrdinal());
		assertTrue(zeroArray2.isEquivalent(comps[3].getDataType()));

		assertEquals(7, comps[4].getOffset());
		assertEquals(8, comps[4].getOrdinal());
		assertTrue(ByteDataType.dataType.isEquivalent(comps[4].getDataType()));
	}

	@Test
	public void testSetName() throws Exception {
		Structure s1 = new StructureDataType("Test1", 0);
		s1.add(new StringDataType(), 5);
		s1.add(new StringDataType(), 10);
		s1.add(new StringDataType(), 15);
		s1.add(new ByteDataType());

		Structure s = (Structure) dataMgr.resolve(s1, null);
		s.setName("NewName");

		assertEquals("NewName", s.getName());
	}

	@Test
	public void testTypedefName() throws Exception {
		Structure s1 = new StructureDataType("Test1", 0);
		s1.add(new StringDataType(), 5);
		s1.add(new StringDataType(), 10);
		TypedefDataType typdef = new TypedefDataType("TypedefToTest1", s1);
		TypeDef td = (TypeDef) dataMgr.resolve(typdef, null);
		assertEquals("TypedefToTest1", td.getName());

		td.setName("NewTypedef");
		assertEquals("NewTypedef", td.getName());
	}

	/**
	 * Test that a structure can't be added to itself.
	 */
	@Test
	public void testCyclicDependencyProblem1() {
		try {
			struct.add(struct);
			Assert.fail("Shouldn't be able to add a structure to itself.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the struct to itself.
		}
		try {
			struct.insert(0, struct);
			Assert.fail("Shouldn't be able to insert a structure into itself.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the struct to itself.
		}
		try {
			struct.replace(0, struct, struct.getLength());
			Assert.fail(
				"Shouldn't be able to replace a structure component with the structure itself.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from replacing the struct to itself.
		}
	}

	/**
	 * Test that a structure array can't be added to the same structure.
	 */
	@Test
	public void testCyclicDependencyProblem2() {
		Array array = createArray(struct, 3);
		try {
			struct.add(array);
			Assert.fail("Shouldn't be able to add a structure array to the same structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the struct to itself.
		}
		try {
			struct.insert(0, array);
			Assert.fail("Shouldn't be able to insert a structure array into the same structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the struct to itself.
		}
		try {
			struct.replace(0, array, array.getLength());
			Assert.fail(
				"Shouldn't be able to replace a structure component with an array of the same structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from replacing the struct to itself.
		}
	}

	/**
	 * Test that a typedef of a structure can't be added to the structure.
	 */
	@Test
	public void testCyclicDependencyProblem3() {
		TypeDef typeDef = createTypeDef(struct);
		try {
			struct.add(typeDef);
			Assert.fail("Shouldn't be able to add a structure typedef to the typedef's structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the struct to itself.
		}
		try {
			struct.insert(0, typeDef);
			Assert.fail(
				"Shouldn't be able to insert a structure typedef into the typedef's structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the struct to itself.
		}
		try {
			struct.replace(0, typeDef, typeDef.getLength());
			Assert.fail(
				"Shouldn't be able to replace a structure component with the structure's typedef.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from replacing the struct to itself.
		}
	}

	/**
	 * Test that a structure can't contain another structure that contains it.
	 */
	@Test
	public void testCyclicDependencyProblem4() {
		Structure anotherStruct = createStructure("AnotherStruct", 0);
		anotherStruct.add(struct);
		try {
			struct.add(anotherStruct);
			Assert.fail(
				"Shouldn't be able to add another structure, which contains this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the struct to itself.
		}
		try {
			struct.insert(0, anotherStruct);
			Assert.fail(
				"Shouldn't be able to insert another structure, which contains this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the struct to itself.
		}
		try {
			struct.replace(0, anotherStruct, anotherStruct.getLength());
			Assert.fail(
				"Shouldn't be able to replace a structure component with another structure which contains this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from replacing the struct to itself.
		}
	}

	/**
	 * Test that a structure can't contain another structure that contains a typedef to it.
	 */
	@Test
	public void testCyclicDependencyProblem5() {
		Structure anotherStruct = createStructure("AnotherStruct", 0);
		TypeDef typeDef = createTypeDef(struct);
		anotherStruct.add(typeDef);
		try {
			struct.add(anotherStruct);
			Assert.fail(
				"Shouldn't be able to add another structure, which contains a typedef of this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the struct to itself.
		}
		try {
			struct.insert(0, anotherStruct);
			Assert.fail(
				"Shouldn't be able to insert another structure, which contains a typedef of this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the struct to itself.
		}
		try {
			struct.replace(0, anotherStruct, anotherStruct.getLength());
			Assert.fail(
				"Shouldn't be able to replace a structure component with another structure which contains a typedef of this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from replacing the struct to itself.
		}
	}

	/**
	 * Test that a structure can't contain a union that contains that structure.
	 */
	@Test
	public void testCyclicDependencyProblem6() {
		Union union = createUnion("TestUnion");
		union.add(struct);
		try {
			struct.add(union);
			Assert.fail(
				"Shouldn't be able to add a union, which contains this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the struct to itself.
		}
		try {
			struct.insert(0, union);
			Assert.fail(
				"Shouldn't be able to insert a union, which contains this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the struct to itself.
		}
		try {
			struct.replace(0, union, union.getLength());
			Assert.fail(
				"Shouldn't be able to replace a structure component with a union, which contains this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from replacing the struct to itself.
		}
	}

	/**
	 * Test that a structure can't contain a typedef of a union that contains that structure.
	 */
	@Test
	public void testCyclicDependencyProblem7() {
		Union union = createUnion("TestUnion");
		union.add(struct);
		TypeDef typeDef = createTypeDef(union);
		try {
			struct.add(typeDef);
			Assert.fail(
				"Shouldn't be able to add a typedef of a union, which contains this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the union typedef to the struct.
		}
		try {
			struct.insert(0, typeDef);
			Assert.fail(
				"Shouldn't be able to insert a typedef of a union, which contains this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the union typedef to the struct.
		}
		try {
			struct.replace(0, typeDef, typeDef.getLength());
			Assert.fail(
				"Shouldn't be able to replace a structure component with a typedef of a union, which contains this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from replacing the struct component with the union typedef.
		}
	}

	/**
	 * Test that a structure can contain a pointer in it to the same structure.
	 */
	@Test
	public void testNoCyclicDependencyProblemForStructurePointer() {
		Pointer structurePointer = createPointer(struct, 4);
		try {
			struct.add(structurePointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail("Should be able to add a structure pointer to the pointer's structure.");
		}
		try {
			struct.insert(0, structurePointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to insert a structure pointer into the pointer's structure.");
		}
		try {
			struct.replace(0, structurePointer, structurePointer.getLength());
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to replace a structure component with the structure's pointer.");
		}
	}

	/**
	 * Test that a structure can contain a pointer in it to a typedef of the same structure.
	 */
	@Test
	public void testNoCyclicDependencyProblemForTypedefPointer() {
		TypeDef typeDef = createTypeDef(struct);
		Pointer typedefPointer = createPointer(typeDef, 4);
		try {
			struct.add(typedefPointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to add a structure typedef pointer to the pointer's structure.");
		}
		try {
			struct.insert(0, typedefPointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to insert a structure typedef pointer into the pointer's structure.");
		}
		try {
			struct.replace(0, typedefPointer, typedefPointer.getLength());
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to replace a structure component with the structure's typedef pointer.");
		}
	}

	/**
	 * Test that a structure can contain a pointer in it to a typedef of the same structure.
	 */
	@Test
	public void testNoCyclicDependencyProblemForArrayPointer() {
		TypeDef typeDef = createTypeDef(struct);
		Array array = createArray(typeDef, 5);
		Pointer arrayPointer = createPointer(array, 4);
		try {
			struct.add(arrayPointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to add a structure typedef array pointer to the pointer's structure.");
		}
		try {
			struct.insert(0, arrayPointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to insert a structure typedef arrayointer into the pointer's structure.");
		}
		try {
			struct.replace(0, arrayPointer, arrayPointer.getLength());
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to replace a structure component with the structure's typedef array pointer.");
		}
	}

	@Test
	public void testNoCyclicDependencyProblemForNestedStruct() {
		Structure child = new StructureDataType(struct.getCategoryPath(), struct.getName(), 0);
		try {
			struct.add(child);
			fail(
				"Should NOT be able to reference same structure within itself based upon equivelency.");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testNoCyclicDependencyProblemForNestedStruct2() throws InvalidNameException {
		StructureDataType child = new StructureDataType("Foo", 0);
		StructureDataType newStruct = new StructureDataType("Tmp", 0);
		newStruct.add(child);
		newStruct.setName("Foo"); // circumvents cyclic check for StructureDataType
		try {
			dataMgr.resolve(newStruct, null);
			fail(
				"Should NOT be able to reference same structure within itself based upon equivelency.");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testGetValue() throws Exception {
		struct = createStructure("Test", 0);

		struct.add(new IntegerDataType(), "field1", "Comment1");
		struct.add(new CharDataType(), "field2", "Comment2");

		ByteMemBufferImpl buf = mb(5, 0, 0, 0, 65);

		Object result = struct.getValue(buf, new SettingsBuilder(), 5);

		assertTrue(result instanceof List);

	    List<?> resultList = (List<?>) result;
	    assertEquals(resultList.size(), 2);

	    assertTrue(resultList.get(0) instanceof Scalar);
	    assertEquals(((Scalar) resultList.get(0)).getValue(), 5);

	    assertTrue(resultList.get(1) instanceof Character);
	    assertEquals(resultList.get(1), 'A');
	}
}
