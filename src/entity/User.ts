import { HashMap } from '@icancode/base';

class User {
  email: string;
  username: string;
  userId: string;

  constructor(data: HashMap = {}) {
    this.email = data['email'] || '';
    this.username = data['username'] || '';
    this.userId = data['userId'] || '';
  }
}

export default User;
