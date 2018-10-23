import java.io.File;
import java.io.FileOutputStream;
import java.util.LinkedHashMap;
import java.util.Properties;

import com.sap.conn.jco.AbapException;
import com.sap.conn.jco.JCoDestination;
import com.sap.conn.jco.JCoDestinationManager;
import com.sap.conn.jco.JCoException;
import com.sap.conn.jco.JCoField;
import com.sap.conn.jco.JCoFieldIterator;
import com.sap.conn.jco.JCoFunction;
import com.sap.conn.jco.JCoStructure;
import com.sap.conn.jco.JCoTable;
import com.sap.conn.jco.ext.DestinationDataProvider;
public class BAPI
{
    static String DESTINATION_NAME1 = "ABAP_AS_WITHOUT_POOL";
    static String DESTINATION_NAME2 = "ABAP_AS_WITH_POOL";
    static
    {
        Properties connectProperties = new Properties();
        connectProperties.setProperty(DestinationDataProvider.JCO_ASHOST, "host");
        connectProperties.setProperty(DestinationDataProvider.JCO_SYSNR,  "02");
        connectProperties.setProperty(DestinationDataProvider.JCO_CLIENT, "001");
        connectProperties.setProperty(DestinationDataProvider.JCO_USER,   "user");
        connectProperties.setProperty(DestinationDataProvider.JCO_PASSWD, "password");
        connectProperties.setProperty(DestinationDataProvider.JCO_LANG,   "en");
        createDestinationDataFile(DESTINATION_NAME1, connectProperties);
        connectProperties.setProperty(DestinationDataProvider.JCO_POOL_CAPACITY, "3");
        connectProperties.setProperty(DestinationDataProvider.JCO_PEAK_LIMIT,    "10");
        createDestinationDataFile(DESTINATION_NAME2, connectProperties);
        
    }
    
    static void createDestinationDataFile(String destinationName, Properties connectProperties)
    {
        File destCfg = new File(destinationName+".jcoDestination");
        try
        {
            FileOutputStream fos = new FileOutputStream(destCfg, false);
            connectProperties.store(fos, "for tests only !");
            fos.close();
        }
        catch (Exception e)
        {
            throw new RuntimeException("Unable to create the destination files", e);
        }
    }
    


    
    
    public static void ReadTable() throws JCoException
    {
        JCoDestination destination = JCoDestinationManager.getDestination(DESTINATION_NAME2);
        JCoFunction func1 = destination.getRepository().getFunction("RFC_READ_TABLE");
        
        
        func1.getImportParameterList().setValue("QUERY_TABLE", "SXMSPFAGG");
        
        
        
        if (func1 == null)
            throw new RuntimeException("RFC_READ_TABLE not found in SAP.");
        try
        {
            func1.execute(destination);
        }
        catch(AbapException e)
        {
            System.out.println(e.toString());
            return;
        }
        

        
        JCoTable dataRecords = func1.getTableParameterList().getTable("DATA");
        
        for (int i = 0; i < dataRecords.getNumRows(); i++)
        {
        	dataRecords.setRow(i);
            JCoFieldIterator iter = dataRecords.getFieldIterator();

            while(iter.hasNextField())
            {
                JCoField f = iter.nextField();
                System.out.println( f.getName() + dataRecords.getValue(f.getName() ) );
            }
            
        }
        
        
        JCoFunction func2 = destination.getRepository().getFunction("RFC_READ_TABLE");
        func2.getImportParameterList().setValue("QUERY_TABLE", "SXMSPFADDRESS");
        
        JCoTable fields = func2.getTableParameterList().getTable("FIELDS");
        fields.appendRow();
        fields.setValue("FIELDNAME", "SERVICE");
        
        fields.appendRow();
        fields.setValue("FIELDNAME", "NAME");

        fields.appendRow();
        fields.setValue("FIELDNAME", "NAMESPACE");

        
        if (func2 == null)
            throw new RuntimeException("RFC_READ_TABLE not found in SAP.");
        try
        {
            func2.execute(destination);
        }
        catch(AbapException e)
        {
            System.out.println(e.toString());
            return;
        }
        
        
        JCoTable dataRecords2 = func2.getTableParameterList().getTable("DATA");
        
        for (int i = 0; i < dataRecords2.getNumRows(); i++)
        {
        	dataRecords2.setRow(i);
            JCoFieldIterator iter = dataRecords2.getFieldIterator();

            while(iter.hasNextField())
            {
                JCoField f = iter.nextField();
                System.out.println( f.getName() + dataRecords2.getValue(f.getName() ) );
            }
            
        }        
        
        
        }
    
    
    
    
    
public static void main (String[] args) throws JCoException{
	
	ReadTable();
}

}
