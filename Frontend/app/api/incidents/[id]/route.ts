import { NextRequest, NextResponse } from "next/server";

type Params = {
  params: Promise<{ id: string }>;
};

type IncidentAction = "true_positive" | "false_positive" | "escalate" | "contain";

function isIncidentAction(value: unknown): value is IncidentAction {
  return value === "true_positive" || value === "false_positive" || value === "escalate" || value === "contain";
}

export async function POST(request: NextRequest, context: Params) {
  const { id } = await context.params;

  try {
    const body = (await request.json()) as { action?: unknown };

    if (!isIncidentAction(body.action)) {
      return NextResponse.json(
        { message: "Invalid action. Expected one of: true_positive, false_positive, escalate, contain." },
        { status: 400 },
      );
    }

    return NextResponse.json({
      incidentId: id,
      action: body.action,
      status: "accepted",
      message: `Action '${body.action}' accepted for incident ${id}.`,
      updatedAt: new Date().toISOString(),
    });
  } catch {
    return NextResponse.json({ message: "Malformed JSON payload." }, { status: 400 });
  }
}
