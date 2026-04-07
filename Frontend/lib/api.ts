export type IncidentAction = "true_positive" | "false_positive" | "escalate" | "contain";

export type IncidentActionResponse = {
  incidentId: string;
  action: IncidentAction;
  status: "accepted" | "failed";
  message: string;
  updatedAt: string;
};

export async function updateIncidentStatus(id: string, action: IncidentAction): Promise<IncidentActionResponse> {
  const response = await fetch(`/api/incidents/${id}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action }),
  });

  const data = (await response.json()) as IncidentActionResponse | { message?: string };

  if (!response.ok) {
    throw new Error(data?.message ?? "Unable to update incident status.");
  }

  return data as IncidentActionResponse;
}
