import configManager from '@/lib/config';
import { NextRequest } from 'next/server';

export const POST = async (req: NextRequest) => {
  try {
    if (configManager.isSetupComplete()) {
      // One-way flag: once setup is complete it cannot be reset via this endpoint
      return Response.json(
        { message: 'Setup is already complete.' },
        { status: 409 },
      );
    }

    configManager.markSetupComplete();

    return Response.json(
      {
        message: 'Setup marked as complete.',
      },
      {
        status: 200,
      },
    );
  } catch (err) {
    console.error('Error marking setup as complete: ', err);
    return Response.json(
      { message: 'An error has occurred.' },
      { status: 500 },
    );
  }
};
