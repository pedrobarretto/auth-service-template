import bcrypt from 'bcrypt';

class AuthApp {
  async hashPassword(password: string) {
    const hashedPassword = await bcrypt.hash(password, 12);
    return hashedPassword;
  }

  async isPasswordValid(
    password: string,
    hashedPassword: string
  ): Promise<boolean> {
    const isValid = await bcrypt.compare(password, hashedPassword);

    if (isValid) return true;

    return false;
  }
}

const authApp = new AuthApp();
export { authApp };
