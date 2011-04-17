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