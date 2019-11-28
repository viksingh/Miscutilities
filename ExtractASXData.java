package com.saki.asx;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;

import org.apache.commons.io.IOUtils;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

/**
 * Example program to list links from a URL.
 */
public class ExtractASXData {
    public static void main(String[] args) throws IOException {
 
    	 String csvFile = "/temp/asxdata/comp.csv";
         BufferedReader br = null;
         String line = "";
         String cvsSplitBy = ",";

         try {

             br = new BufferedReader(new FileReader(csvFile));
             while ((line = br.readLine()) != null) {

                 // use comma as separator
                 String[] company = line.split(cvsSplitBy);
                 String compASXcode = company[1];
                 
                 String compCodeClean = compASXcode.replaceAll("\"","");

//                 System.out.println(" Code = " + compCodeClean );
                 
                 String compURL = "https://www.asx.com.au/asx/1/share/"+compCodeClean+"/prices?interval=daily&count=1" ;


                 
             	try {
					URL url = new URL(compURL);
					URLConnection con = url.openConnection();
					InputStream in = con.getInputStream();
					String encoding = con.getContentEncoding();
					encoding = encoding == null ? "UTF-8" : encoding;
					String body = IOUtils.toString(in, encoding);
					String toProcess = body.replace("\"data\":","").replace("{[","[").replace("]}","]");
					
					 Gson gson=new Gson();

					 Type CompanyCodeListType = new TypeToken<ArrayList<CompanyData>>(){}.getType();
					 
					 ArrayList<CompanyData> compData = new ArrayList<CompanyData>(); 
					 
					 compData = gson.fromJson(toProcess, CompanyCodeListType);  	
					 
					 
	                 
					
					
					  for (  CompanyData company1 : compData) 
					  
					  { 
						  
						  System.out.println(company1.getCode() + "  ***  "+ company1.getChange_in_percent()  + "  ***  "+ company1.getChange_price() +"  *** " +  + company1.getClose_price() );
					  
					  }
					 
					
				} catch (Exception e) {
//				e.printStackTrace();
				}                 

             }

         } catch (FileNotFoundException e) {
         } catch (IOException e) {
         } finally {
             if (br != null) {
                 try {
                     br.close();
                 } catch (IOException e) {
                 }
             }
         }    	
    	
    	
    	
    	
    	

    	
}
}
