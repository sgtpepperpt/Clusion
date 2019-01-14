/** * Copyright (C) 2016 Tarik Moataz
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

//***********************************************************************************************//

// This file contains the step-by-step local benchmarking of the IEX-2Lev. The encrypted data structure remains in the RAM.
// This file also gathers stats useful to give some insights about the scheme implementation
// One needs to wait until the complete creation of the encrypted data structures of IEX-2Lev in order to issue queries.
// Queries need to be in the form of CNF. Follow on-line instructions
//***********************************************************************************************//
package org.crypto.sse;

import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.NoSuchPaddingException;

public class TestLocalIEX2Lev {

	public static void main(String[] args) throws Exception {

		//BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));

		//System.out.println("Enter your password :");

		String pass = "1234";

		List<byte[]> listSK = IEX2Lev.keyGen(256, pass, "salt/salt", 100);

		long startTime = System.nanoTime();

		BufferedWriter writer = new BufferedWriter(new FileWriter("logs.txt", true));

		//System.out.println("Enter the relative path name of the folder that contains the files to make searchable: ");

		String pathName = "/localssd/gborges/BISEN/Data/parsed/" + args[0];
System.out.println(pathName);
		// Creation of different files based on selectivity
		// Selectivity was computed in an inclusive way. All files that include
		// x(i+1) include necessarily xi
		// This is used for benchmarking and can be taken out of the code

		ArrayList<File> listOfFile = new ArrayList<File>();
		TextProc.listf(pathName, listOfFile);

		TextProc.TextProc(false, pathName);

		int bigBlock = 1000;
		int smallBlock = 100;

		long startTime2 = System.nanoTime();

		IEX2Lev disj = IEX2Lev.setup(listSK, TextExtractPar.lp1, TextExtractPar.lp2, bigBlock, smallBlock, 0);

		long endTime2 = System.nanoTime();
		long totalTime2 = endTime2 - startTime2;

		// Writing logs

		System.out.println("\n!*****************************************************************");
		System.out.println("\n\t\t!STATS");
		System.out.println("\n!*****************************************************************");

		// System.out.println("\nNumber of keywords
		// "+TextExtractPar.totalNumberKeywords);
		System.out.println("\nNumber of (w, id) pairs " + TextExtractPar.lp2.size());
		writer.write("\n Number of (w, id) pairs " + TextExtractPar.lp2.size());

		System.out.println("\nTotal number of stored (w, Id) including in local MM : " + IEX2Lev.numberPairs);
		writer.write("\n Total number of stored (w, Id) including in local MM : " + IEX2Lev.numberPairs);

		System.out.println("\nTime elapsed per (w, Id) in ns: " + totalTime2 / IEX2Lev.numberPairs);
		writer.write("\n Time elapsed per (w, Id) in ns: " + totalTime2 / IEX2Lev.numberPairs);

		System.out.println("\nTotal Time elapsed for the entire construction in seconds: " + totalTime2 / 1000000000);
		writer.write("\n Total Time elapsed for the entire construction in seconds: " + totalTime2 / 1000000000);

		System.out.println("\nRelative Time elapsed per (w, Id) in ns: " + totalTime2 / TextExtractPar.lp1.size());
		writer.write("\n Relative Time elapsed per (w, Id) in ns: " + totalTime2 / TextExtractPar.lp1.size());

		// The two commented commands are used to compute the size of the
		// encrypted Local multi-maps and global multi-maps

		// System.out.println("\nSize of the Structure LMM: "+
		// SizeOf.humanReadable(SizeOf.deepSizeOf(disj.getLocalMultiMap())));
		// System.out.println("\nSize of the Structure MMg: "+
		// SizeOf.humanReadable(SizeOf.deepSizeOf(disj.getGlobalMM())));
		writer.close();

        System.out.print("\n!DONE UPDATE\n");

        System.out.printf("\n!AND TEST 10 kw %s docs\n", args[0]);
        String[][] bool = new String[10][1];
        bool[0][0] = "enron";
        bool[1][0] = "time";
        bool[2][0] = "inform";
        bool[3][0] = "work";
        bool[4][0] = "call";
        bool[5][0] = "discuss";
        bool[6][0] = "meet";
        bool[7][0] = "week";
        bool[8][0] = "receiv";
        bool[9][0] = "dai";
        test("log-1.txt", 1, disj, listSK, bool);

        System.out.printf("\n!OR TEST 10 kw %s docs\n", args[0]);
        bool = new String[1][10];
        bool[0][0] = "enron";
        bool[0][1] = "time";
        bool[0][2] = "inform";
        bool[0][3] = "work";
        bool[0][4] = "call";
        bool[0][5] = "discuss";
        bool[0][6] = "meet";
        bool[0][7] = "week";
        bool[0][8] = "receiv";
        bool[0][9] = "dai";
        test("log-2.txt", 1, disj, listSK, bool);

        System.out.printf("\n!CNF TEST 8 kw %s docs\n", args[0]);
        bool = new String[4][2];
        bool[0][0] = "enron";
        bool[0][1] = "time";
        bool[1][0] = "inform";
        bool[1][1] = "work";
        bool[2][0] = "call";
        bool[2][1] = "discuss";
        bool[3][0] = "meet";
        bool[3][1] = "week";
        test("log-3.txt", 1, disj, listSK, bool);

        System.out.printf("\n!DNF TEST 8 kw %s docs\n", args[0]);
        bool = new String[2][4];
        bool[0][0] = "enron";
        bool[0][1] = "time";
        bool[0][2] = "inform";
        bool[0][3] = "work";
        bool[1][0] = "call";
        bool[1][1] = "discuss";
        bool[1][2] = "meet";
        bool[1][3] = "week";
        test("log-4.txt", 1, disj, listSK, bool);

        System.out.print("\n!END\n");

	}

	public static void test(String output, int numberIterations, IEX2Lev disj, List<byte[]> listSK,
			String[][] bool) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, UnsupportedEncodingException, IOException {

		long minimum = 1000000000;
		long maximum = 0;
		long average = 0;

		// Generate the IEX token
		List<String> searchBol = new ArrayList<String>();
		for (int i = 0; i < bool[0].length; i++) {
			searchBol.add(bool[0][i]);
		}

		for (int g = 0; g < numberIterations; g++) {

			// Generation of stream file to measure size of the token

			long startTime3 = System.nanoTime();

			// System.out.println(searchBol);

			Set<String> tmpBol = IEX2Lev.query(IEX2Lev.token(listSK, searchBol), disj);

			// System.out.println(tmpBol);

			for (int i = 1; i < bool.length; i++) {
				Set<String> finalResult = new HashSet<String>();
				for (int k = 0; k < bool[0].length; k++) {
					List<String> searchTMP = new ArrayList<String>();
					searchTMP.add(bool[0][k]);
					for (int r = 0; r < bool[i].length; r++) {
						searchTMP.add(bool[i][r]);
					}

					List<TokenDIS> tokenTMP = IEX2Lev.token(listSK, searchTMP);

					Set<String> result = new HashSet<String>(RR2Lev.query(tokenTMP.get(0).getTokenMMGlobal(),
							disj.getGlobalMM().getDictionary(), disj.getGlobalMM().getArray()));

					if (!(tmpBol.size() == 0)) {
						List<Integer> temp = new ArrayList<Integer>(
								disj.getDictionaryForMM().get(new String(tokenTMP.get(0).getTokenDIC())));

						if (!(temp.size() == 0)) {
							int pos = temp.get(0);

							for (int j = 0; j < tokenTMP.get(0).getTokenMMLocal().size(); j++) {

								Set<String> temporary = new HashSet<String>();
								List<String> tempoList = RR2Lev.query(tokenTMP.get(0).getTokenMMLocal().get(j),
										disj.getLocalMultiMap()[pos].getDictionary(),
										disj.getLocalMultiMap()[pos].getArray());

								if (!(tempoList == null)) {
									temporary = new HashSet<String>(
											RR2Lev.query(tokenTMP.get(0).getTokenMMLocal().get(j),
													disj.getLocalMultiMap()[pos].getDictionary(),
													disj.getLocalMultiMap()[pos].getArray()));
								}

								finalResult.addAll(temporary);

								if (tmpBol.isEmpty()) {
									break;
								}

							}
						}

					}
				}
				tmpBol.retainAll(finalResult);

			}

			System.out.println("Final result " + tmpBol);
			long endTime3 = System.nanoTime();
			long totalTime3 = endTime3 - startTime3;

			if (totalTime3 < minimum) {

				minimum = totalTime3;

			}

			if (totalTime3 > maximum) {

				maximum = totalTime3;

			}

			average = average + totalTime3;

		}

		BufferedWriter writer2 = new BufferedWriter(new FileWriter(output, true));
		writer2.write("\nminimum " + minimum);
		writer2.write("\nmaximum " + maximum);
		writer2.write("\naverage " + average / numberIterations + "\n\n");
        System.out.println("\n!elapsed " + (average / numberIterations / 1000) + "\n\n");
		writer2.close();

	}

}

/*
 * Code Below used for Benchmarking
 */

// public static ArrayList<String> list = new ArrayList<String>() {{
// add("iex15");
// add("iex50");
// add("iex100");
// add("iex500");
// add("iex1000");
// add("iex2000");
// add("iex10000");
// }};

// int select = 0;
//
//
// for (File file:listOfFile){
// PrintWriter pw = null;
// if (select<listOfFile.size()){
// try {
// FileWriter fw = new FileWriter(file, true);
// pw = new PrintWriter(fw);
//
// if (select<15){
// pw.println(" iex15");
// }
//
// if (select<50){
//
// pw.println(" iex50");
//
// }
//
// if (select<100){
// pw.println(" iex100");
//
// }
//
// if (select<500){
// pw.println(" iex500");
//
// }
//
// if (select<1000){
// pw.println(" iex1000");
//
// }
//
// if (select<2000){
// pw.println(" iex2000");
//
// }
//
// if (select<listOfFile.size()){
// pw.println(" iex10000");
//
// }
//
// } catch (IOException e) {
// e.printStackTrace();
// } finally {
// if (pw != null) {
// pw.close();
// }
// }
//
// select =select+1;
// }
// }

// Beginning of test phase

// Conjunctive test for Selectivity 15: w AND x where DB(w) =15

// System.out.println("Conjunctive Test");
// for (String word : list){
// String[][] bool = new String[2][1];
// bool[0][0] = "iex15";
// bool[1][0] = word;
// test("logC15-1.txt",word,50,disj,listSK,bool);
// }
//
//
//// Conjunctive test for Selectivity 15: w AND x where DB(w) = 2000
//
//
// for (String word : list){
// String[][] bool = new String[2][1];
// bool[0][0] = "iex2000";
// bool[1][0] = word;
// test("logC2000-1.txt",word,50,disj,listSK,bool);
// }
//
//// Conjunctive test for Selectivity 15: w AND x where DB(x) = 15
//
// for (String word : list){
// String[][] bool = new String[2][1];
// bool[1][0] = "iex15";
// bool[0][0] = word;
// test("logC15-2.txt",word,50,disj,listSK,bool);
// }
//
//
//// Conjunctive test for Selectivity 15: w AND x where DB(x) = 2000
//
// for (String word : list){
// String[][] bool = new String[2][1];
// bool[1][0] = "iex2000";
// bool[0][0] = word;
// test("logC2000-2.txt",word,50,disj,listSK,bool);
// }
// System.out.println("Disjunctive Test");
//
//
//// Disjunctive test for Selectivity 15: w OR x where DB(w) = 15
//
// for (String word : list){
// String[][] bool = new String[1][2];
// bool[0][0] = "iex15";
// bool[0][1] = word;
// test("logD15.txt",word,50,disj,listSK,bool);
// }
//
//// Disjunctive test for Selectivity 15: w OR x where DB(w) = 2000
//
// for (String word : list){
// String[][] bool = new String[1][2];
// bool[0][0] = "iex2000";
// bool[0][1] = word;
// test("logD2000.txt",word,50,disj,listSK,bool);
// }
//
// System.out.println("Boolean Test");
//
//
//// Boolean test for selectivity 15: (w OR x) AND (y or z) DB(w Or x) = 15
//
// for (String word : list){
// String[][] bool = new String[2][2];
// bool[0][0] = "iex15";
// bool[0][1] = "iex15";
// bool[1][0] = word;
// bool[1][1] = word;
// test("logB15.txt",word,50,disj,listSK,bool);
// }
//
//
//// Boolean test for selectivity 15: (w OR x) AND (y or z) DB(w Or x) = 15
//
//
// for (String word : list){
// String[][] bool = new String[2][2];
// bool[0][0] = "iex2000";
// bool[0][1] = "iex2000";
// bool[1][0] = word;
// bool[1][1] = word;
// test("logB2000.txt",word,50,disj,listSK,bool);
// }
