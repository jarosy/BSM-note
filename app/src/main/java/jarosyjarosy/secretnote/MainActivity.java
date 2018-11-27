package jarosyjarosy.secretnote;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.security.KeyPairGeneratorSpec;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.widget.*;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.*;

import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;

public class MainActivity extends AppCompatActivity {

    private static final String AndroidKeyStore = "AndroidKeyStore";
    private static final String KEY_ALIAS = "BSM_NOTE";

    private boolean doubleBackToExitPressedOnce = false;

    private KeyStore keyStore;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            setKeyStore();
            openAlertDialog();
        } catch (Exception e) {
            e.printStackTrace();
        }

        Button loginBtn = findViewById(R.id.loginButton);
        Button resetBtn = findViewById(R.id.resetButton);
        EditText passwordInput = findViewById(R.id.passwordInput);
        TextView noteText = findViewById(R.id.noteText);

        loginBtn.setOnClickListener(v -> {
            SharedPreferences sharedPref = this.getPreferences(Context.MODE_PRIVATE);
            try {
                if (PasswordUtils.verify(passwordInput.getText().toString(), sharedPref.getString("pass", "error"))) {
                    noteText.setText(decrypt(sharedPref.getString("note", "error")));
                    resetBtn.setEnabled(true);
                    Toast.makeText(this, "Hasło prawidłowe", Toast.LENGTH_LONG).show();
                } else {
                    Toast.makeText(this, "Błędne hasło", Toast.LENGTH_LONG).show();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        resetBtn.setOnClickListener(v -> {
            SharedPreferences sharedPref = this.getPreferences(Context.MODE_PRIVATE);
            sharedPref.edit().clear().commit();
            try {
                keyStore.deleteEntry(KEY_ALIAS);
                setKeyStore();
                openAlertDialog();
                resetBtn.setEnabled(false);
                passwordInput.getText().clear();
                noteText.setText("...");

            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        });

    }

    private void openAlertDialog() {
        SharedPreferences sharedPref = this.getPreferences(Context.MODE_PRIVATE);
        if (!sharedPref.getBoolean("passSet", false)) {
            Toast.makeText(this, "Ustaw notatke i haslo", Toast.LENGTH_LONG).show();
            AlertDialog.Builder newAlertBuild = new AlertDialog.Builder(MainActivity.this);
            View dialogView = getLayoutInflater().inflate(R.layout.note_edit, null);

            newAlertBuild.setView(dialogView);
            AlertDialog newDialog = newAlertBuild.create();
            newDialog.show();
            newDialog.setCanceledOnTouchOutside(false);
            newDialog.setCancelable(false);

            EditText editPass = dialogView.findViewById(R.id.setPassword);
            EditText editNote = dialogView.findViewById(R.id.setNote);
            Button setPassBtn = dialogView.findViewById(R.id.setNotePasswordBtn);

            setPassBtn.setOnClickListener(v -> {
                if(!editPass.getText().toString().isEmpty() && !editNote.getText().toString().isEmpty()){
                    SharedPreferences.Editor editor = sharedPref.edit();
                    try {
                        editor.putString("pass", PasswordUtils.hash(editPass.getText().toString()));
                        editor.putString("note", encrypt(editNote.getText().toString()));
                        editor.putBoolean("passSet", true);
                        editor.commit();
                        newDialog.dismiss();

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else {
                    Toast.makeText(this, "Uzupełnij notatkę i hasło", Toast.LENGTH_LONG).show();
                }
            });
        }
    }

    private void setKeyStore() {
        try {
            keyStore = KeyStore.getInstance(AndroidKeyStore);
            keyStore.load(null);
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 1);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(this)
                        .setAlias(KEY_ALIAS)
                        .setSubject(new X500Principal("CN=Sample Name, O=BSM"))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                generator.initialize(spec);

                KeyPair keyPair = generator.generateKeyPair();
            }
        } catch (Exception e) {
            Toast.makeText(this, "Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
        }
    }



    private String encrypt(String string) throws Exception {

            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(KEY_ALIAS, null);
            RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

            Cipher input = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            input.init(Cipher.ENCRYPT_MODE, publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, input);
            cipherOutputStream.write(string.getBytes("UTF-8"));
            cipherOutputStream.close();

            byte [] vals = outputStream.toByteArray();
            return Base64.encodeToString(vals, Base64.DEFAULT);
    }

    private String decrypt(String cipherText) throws Exception{
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(KEY_ALIAS, null);

            Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());

            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(cipherText, Base64.DEFAULT)), output);
            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte)nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for(int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i);
            }

            return new String(bytes, 0, bytes.length, "UTF-8");
    }

    @Override
    public void onBackPressed() {
        if (doubleBackToExitPressedOnce) {
            finishAffinity();
            return;
        }

        this.doubleBackToExitPressedOnce = true;
        Toast.makeText(this, "Wciśnij WSTECZ ponownie, aby wyjść.", Toast.LENGTH_SHORT).show();

        new Handler().postDelayed(new Runnable() {

            @Override
            public void run() {
                doubleBackToExitPressedOnce = false;
            }
        }, 2000);
    }

}
