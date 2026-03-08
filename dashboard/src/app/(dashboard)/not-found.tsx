/**
 * Dashboard Not Found Page
 *
 * Provides a user-friendly 404 page for dashboard routes.
 *
 * @author Erick | Founding Principal AI Architect
 */

import Link from 'next/link';
import { FileQuestion, Home, ArrowLeft } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';

export default function DashboardNotFound() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardContent className="pt-8 text-center">
          <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full bg-muted">
            <FileQuestion className="h-8 w-8 text-muted-foreground" />
          </div>

          <h2 className="mb-2 text-xl font-bold">Page Not Found</h2>

          <p className="mb-6 text-muted-foreground">
            The page you&apos;re looking for doesn&apos;t exist or has been moved.
          </p>

          <div className="flex flex-col gap-3 sm:flex-row sm:justify-center">
            <Link href="/">
              <Button className="gap-2">
                <Home className="h-4 w-4" />
                Go to Dashboard
              </Button>
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
