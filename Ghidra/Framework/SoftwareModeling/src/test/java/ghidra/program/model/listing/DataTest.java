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
package ghidra.program.model.listing;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.Address;

public class DataTest extends AbstractGenericTest {
    private TestData testData;
    private Program mockProgram;
    private Address mockAddress;

    @Before
    public void setUp() throws Exception {
    	mockProgram = createMockProgram();
        testData = new TestData(mockProgram);
        mockAddress = mock(Address.class);
    }

    private Program createMockProgram() {
        Program program = mock(Program.class);
        
        Listing mockListing = mock(Listing.class);
        when(program.getListing()).thenReturn(mockListing);

        doAnswer(invocation -> {
            Address addr = invocation.getArgument(0);
            return testData.getCodeUnitAt(addr);
        }).when(mockListing).getCodeUnitAt(any(Address.class));
        
        return program;
    }

    @Test
    public void testNullValue() {
        testData.setTestValue(null);
        assertNull(testData.getValueAsCObject());
    }

    @Test
    public void testStringValue() {
        testData.setTestValue("Hello World");
        assertEquals("\"Hello World\"", testData.getValueAsCObject());
    }

    @Test
    public void testCharacterValue() {
        testData.setTestValue('A');
        assertEquals("'A'", testData.getValueAsCObject());
        
        testData.setTestValue('\n');
        assertEquals("'\\n'", testData.getValueAsCObject());
    }

    @Test
    public void testNumericValue() {
        testData.setTestValue(123);
        assertEquals("123", testData.getValueAsCObject());
        
        testData.setTestValue(3.14);
        assertEquals("3.14", testData.getValueAsCObject());
    }

    @Test
    public void testListValue() {
    	List<?> list = Arrays.asList(1, 2, 3);
        testData.setTestValue(list);
        assertEquals("{1, 2, 3}", testData.getValueAsCObject());

        list = Arrays.asList(1, "two", '3');
        testData.setTestValue(list);
        assertEquals("{1, \"two\", '3'}", testData.getValueAsCObject());
    }

    @Test
    public void testNestedListValue() {
        List<?> innerList = Arrays.asList('a', 'b');
        List<?> list = Arrays.asList(innerList, innerList);
        testData.setTestValue(list);
        assertEquals("{{'a', 'b'}, {'a', 'b'}}", testData.getValueAsCObject());
    }

    @Test
    public void testAddressValue_PointsToStringData() {
        TestData stringData = new TestData(mockProgram);
        stringData.setTestValue("TestString");
        stringData.setHasStringValue(true);

        testData.setCodeUnitAt(mockAddress, stringData);

        testData.setTestValue(mockAddress);

        assertEquals("\"TestString\"", testData.getValueAsCObject());
    }

    @Test
    public void testAddressValue() {
        CodeUnit mockCodeUnit = mock(CodeUnit.class);
        when(mockCodeUnit.getLabel()).thenReturn("dataLabel");

        testData.setCodeUnitAt(mockAddress, mockCodeUnit);

        testData.setTestValue(mockAddress);
        testData.setIsPointer(true);
        
        assertEquals("&dataLabel", testData.getValueAsCObject());
    }

    private class TestData extends DataStub {
        private Object testValue;
        private Program testProgram;
        private CodeUnit codeUnitAt;
        private boolean isPointer;
        private boolean hasStringValue;
        
        public void setIsPointer(boolean isPointer) {
            this.isPointer = isPointer;
        }
        
        public void setHasStringValue(boolean hasStringValue) {
            this.hasStringValue = hasStringValue;
        }
        
        public TestData(Program program) {
            this.testProgram = program;
        }
        
        public void setTestValue(Object value) {
            this.testValue = value;
        }
        
        public void setCodeUnitAt(Address address, CodeUnit codeUnit) {
            this.codeUnitAt = codeUnit;
        }
        
        public CodeUnit getCodeUnitAt(Address address) {
            return codeUnitAt;
        }
        
        @Override
        public boolean isPointer() {
            return isPointer;
        }
        
        @Override
        public boolean hasStringValue() {
            return hasStringValue;
        }

        @Override
        public Object getValue() {
            return testValue;
        }

        @Override
        public Program getProgram() {
            return testProgram;
        }
    }
}
