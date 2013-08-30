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

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup.LayoutParams;
import android.widget.Button;
import android.widget.LinearLayout;

public class masonExpCtlClient extends Activity {
	
	public static final String TAG = "masonExpCtlClient";
    
	LinearLayout ll;
	Button stop;
	Button start;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		initializeGUI();
		initializeCallbacks();
	}

	private void initializeGUI() {
		ll = new LinearLayout(this);
		ll.setLayoutParams(new LayoutParams(LayoutParams.FILL_PARENT,
				LayoutParams.FILL_PARENT));
		ll.setOrientation(LinearLayout.VERTICAL);

		start = new Button(this);
		stop = new Button(this);

		start.setText("Start MasonExpCtlClient");
		stop.setText("Stop MasonExpCtlClient");
		
		ll.addView(start);
		ll.addView(stop);

		setContentView(ll);
	}

	private void initializeCallbacks() {
		final Intent intent = new Intent("whisper.mason.expctl.masonExpCtlClientService");
		start.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {
				masonExpCtlClient.this.startService(intent);
			}
		});
		
		stop.setOnClickListener(new OnClickListener() {
			public void onClick(View v) {
				masonExpCtlClient.this.stopService(intent);
			}
		});
	}
	
    
}
