package pt.unl.fct.di.adc.firstwebapp.util;

public class CreateAccountData {

	public String username;
	public String password;
	public String confirmation;
	public String phone;
	public String address;
	public String role;

	public CreateAccountData() {}

	private boolean notBlank(String s) {
		return s != null && !s.isBlank();
	}

	public boolean isValid() {
		return notBlank(username)
				&& notBlank(password)
				&& notBlank(confirmation)
				&& password.equals(confirmation)
				&& username.contains("@")
				&& notBlank(role)
				&& (role.equals("USER") || role.equals("BOFFICER") || role.equals("ADMIN"));
	}
}
