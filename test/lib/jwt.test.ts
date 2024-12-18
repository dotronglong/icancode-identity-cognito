import { signRSA, verifyRSA } from '../../src/lib/jwt';

describe('lib/jwt', () => {
  let token: string;
  const payload = { userId: 'test-user-id', email: 'test@domain.com' };

  beforeAll(() => {
    // eslint-disable-next-line
    require('dotenv').config();
  });

  describe('signRSA', () => {
    it('should be able to sign payload using RSA algorithm', async () => {
      token = await signRSA(payload);
      expect(token).toBeDefined();
    });
  });

  describe('verifyRSA', () => {
    it('should be able to sign payload using RSA algorithm', async () => {
      const decodedPayload = await verifyRSA(token);
      expect(decodedPayload).toEqual(payload);
    });
  });
});
