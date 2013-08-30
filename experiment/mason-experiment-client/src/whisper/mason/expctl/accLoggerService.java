/*
 * Copyright 2011 The Regents of the University of Michigan
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

package whisper.mason.expctl;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.RandomAccessFile;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.os.IBinder;
import android.util.Log;

//accLogger service
public class accLoggerService extends Service implements SensorEventListener{
	
	public static final String TAG = "accLoggerService";
	
	// The length (bytes number) we get from the end of "/sdcard/masond.log" 
	// to get the rnd 
	private static final int LINELEN=100; 
	
	private SensorManager sensors;
	private Sensor accel;
	private Sensor magf;
	private Sensor ori;
	private BufferedWriter writerAcc;
	private BufferedWriter writerMag;
	private BufferedWriter writerOri;
	
	public void onCreate() {
		super.onCreate();
		
		Log.e(TAG,"Start logger service!");
		
		// Register this class to get accelerometer,  data as fast as possible
		sensors = (SensorManager) this.getSystemService(Context.SENSOR_SERVICE);
		accel = sensors.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
		sensors.registerListener(this, accel,
				SensorManager.SENSOR_DELAY_UI);
		magf = sensors.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD);
		sensors.registerListener(this, magf,
				SensorManager.SENSOR_DELAY_UI);
		ori = sensors.getDefaultSensor(Sensor.TYPE_ORIENTATION);
		sensors.registerListener(this, ori,
				SensorManager.SENSOR_DELAY_UI);
		
		
		//open the log file
		try {
			File logFileAcc = new File("/sdcard/accLogger-mason-acc");
			logFileAcc.createNewFile();
			this.writerAcc = new BufferedWriter(new FileWriter(logFileAcc,true));
			File logFileMag = new File("/sdcard/accLogger-mason-mag");
			logFileMag.createNewFile();
			this.writerMag = new BufferedWriter(new FileWriter(logFileMag,true));
			File logFileOri = new File("/sdcard/accLogger-mason-ori");
			logFileOri.createNewFile();
			this.writerOri = new BufferedWriter(new FileWriter(logFileOri,true));
		} catch (Exception e) {
			Log.e(TAG, "Cannot open log files, Error:" + e);
			stopSelf();
		}
	}
	
	//Read the last few bytes of the "/sdcard/masond.log" file and get the rnd
	private String getRnd(String fileName, int lineLen){
		
		String line = null;
		
		//Get the corresponding string of the last lineLen bytes of fileName
		try{
			File f = new File(fileName);
			RandomAccessFile raf = new RandomAccessFile(f,"r");
			long offset = f.length()-lineLen;
			if(offset<0){
				return null;
			}
			raf.seek(offset);
			byte[] buffer = new byte[lineLen];
			raf.read(buffer);
			line = new String(buffer);
		}catch(IOException el){
			stopSelf();
			
		}
		
        //Parse the line to get the rnd
        String[] tokens = line.split(" ");
		for(String t : tokens){
			if(t.contains("rnd")){
				String[] rounds = t.split(":");
				return rounds[1]; 
			}
		}
		
		return null;
		 
	}
	
	public void onStart(Intent intent, int startId){
		super.onStart(intent, startId);
		
		//Get the round id from "/sdcard/masond.log"
		String rnd = "Last round: " + getRnd("/sdcard/masond.log", LINELEN);
		Log.e(TAG,"Start logging for new round: "+rnd);
		
		//Log the description
		try {
			accLoggerService.this.writerAcc.newLine();
			accLoggerService.this.writerAcc.write(rnd);
			accLoggerService.this.writerAcc.newLine();
			accLoggerService.this.writerMag.newLine();
			accLoggerService.this.writerMag.write(rnd);
			accLoggerService.this.writerMag.newLine();
			accLoggerService.this.writerOri.newLine();
			accLoggerService.this.writerOri.write(rnd);
			accLoggerService.this.writerOri.newLine();
		} catch (IOException e) {
			Log.e(TAG, "Cannot write to log files, Error:" + e.getMessage());
			stopSelf();
		} 
		
		Log.e(TAG,"The description successfully logged!");
	}

	@Override
	public void onDestroy() {
		
		super.onDestroy();
		
		//unregister the listener
		sensors.unregisterListener(this);
		
		//close file
		try {
			writerAcc.flush();
			writerAcc.close();
			writerMag.flush();
			writerMag.close();
			writerOri.flush();
			writerOri.close();
		} catch (IOException e) {
			Log.e(TAG, "Cannot close log file, Error:" + e.getMessage());
		}

		
	}


	@Override
	public IBinder onBind(Intent intent) {
		return null;
	}

	public void onAccuracyChanged(Sensor sensor, int accuracy) {
		// Ignore
	}

	public void onSensorChanged(SensorEvent event) {
		
		//Log.e(TAG,"Sensor reading changed!");
		
		String TimeCrt = Long.toString(System.currentTimeMillis());
		
		String line = TimeCrt + " " +
		Float.toString(event.values[0]) + " " + 
		Float.toString(event.values[1]) + " " + 
		Float.toString(event.values[2]);
		
		//Log.e(TAG, line);
		
		//Write the accelerometer changes to log file
		try {
			switch(event.sensor.getType()){
				case Sensor.TYPE_ACCELEROMETER:
					writerAcc.write(line);
					writerAcc.newLine();
					break;
				case Sensor.TYPE_MAGNETIC_FIELD:
					writerMag.write(line);
					writerMag.newLine();
					break;
				case Sensor.TYPE_ORIENTATION:
					writerOri.write(line);
					writerOri.newLine();
					break;
			}
		} catch (IOException e) {
			Log.e(TAG, "Cannot write to log files, Error:" + e.getMessage());
			stopSelf();
		} 

	}

}
