package pt.unl.fct.di.adc.firstwebapp.util;

public class ChangePasswordData {

    public String username;
    public String oldPassword;
    public String newPassword;

    public ChangePasswordData() {}

    public boolean isValid() {
        return newPassword != null && !newPassword.isBlank();
    }
}
