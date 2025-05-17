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
package ghidra.program.model.data;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.mem.*;
import ghidra.program.model.mem.StubMemory;
import ghidra.program.model.scalar.Scalar;

public class ArrayGetValueTest extends AbstractGTest {
	private ByteMemBufferImpl mb(int... values) {
		GenericAddressSpace gas = new GenericAddressSpace("test", 32, AddressSpace.TYPE_RAM, 1);
		Memory mem = new TestMemory(gas.getMinAddress(), gas.getMaxAddress());
		return new ByteMemBufferImpl(mem, gas.getAddress(0), bytes(values), false);
	}

	private SettingsBuilder newset() {
		return new SettingsBuilder();
	}

	private static class DataOrgDTM extends TestDummyDataTypeManager {
		private DataOrganization dataOrg;

		public DataOrgDTM(int size) {
			DataOrganizationImpl dataOrgImpl = DataOrganizationImpl.getDefaultOrganization(null);
			dataOrgImpl.setCharSize(size);

			this.dataOrg = dataOrgImpl;
		}

		@Override
		public DataOrganization getDataOrganization() {
			return dataOrg;
		}
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

	private Array mkArray(DataTypeManager dtm, int count, DataType dt) {
		Array arrayDT = new ArrayDataType(dt, count, dt.getLength(), dtm);

		return arrayDT;
	}
	
	private void AssertArrayEquals(int[] expected, List<?> reuslt)
	{
		assertEquals(expected.length, reuslt.size());
	    for (int i = 0; i < expected.length; i++) {
	    	assertTrue(reuslt.get(i) instanceof Scalar);
	        assertEquals(expected[i], ((Scalar) reuslt.get(i)).getValue());
	    }
	}

	private DataTypeManager intDTM = new DataOrgDTM(4);
	private Array array2int = mkArray(intDTM, 2, new IntegerDataType(intDTM));
	private Array array2array2int = mkArray(intDTM, 2, array2int);

	@Test
	public void testGetValue_intArray() {
		ByteMemBufferImpl buf = mb(1, 0, 0, 0, 2, 0, 0, 0);
		int[] expected = {1, 2};
		Object result = array2int.getArrayValue(buf, newset(), array2int.getLength());
	    assertTrue(result instanceof List);

	    List<?> resultList = (List<?>) result;
	    AssertArrayEquals(expected, resultList);
	}

	@Test
	public void testGetValue_intMatrix() {
		ByteMemBufferImpl buf = mb(1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0);		
		int[][] expected = {{1, 2}, {3, 4}};
		Object result = array2array2int.getArrayValue(buf, newset(), array2array2int.getLength());
	    assertTrue(result instanceof List);

	    List<?> resultList = (List<?>) result;
	    assertEquals(expected.length, resultList.size());
	    for (int i = 0; i < expected.length; i++) {
	    	assertTrue(resultList.get(i) instanceof List);
	    	AssertArrayEquals(expected[i], ((List<?>) resultList.get(i)));
	    }
	}
}
