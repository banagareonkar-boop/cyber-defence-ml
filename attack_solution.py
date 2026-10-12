# ==========================================
# Cyber Defence - Attack Solution Module
# ==========================================

def get_attack_solution(attack_category):

    solutions = {

        "DoS": {
            "severity": "High",
            "action": "Rate limiting and suspicious traffic monitoring",
            "solution": (
                "Monitor high-volume traffic, apply rate limiting, "
                "and identify suspicious source addresses."
            )
        },

        "Probe": {
            "severity": "Medium",
            "action": "Port scanning detection and source monitoring",
            "solution": (
                "Monitor repeated connection attempts and suspicious "
                "port scanning activity."
            )
        },

        "R2L": {
            "severity": "High",
            "action": "Authentication and access-control monitoring",
            "solution": (
                "Strengthen authentication, monitor failed login attempts, "
                "and restrict unauthorized access."
            )
        },

        "U2R": {
            "severity": "Critical",
            "action": "Privilege monitoring",
            "solution": (
                "Monitor privilege escalation, restrict administrator "
                "access, and investigate suspicious privileged activity."
            )
        },

        "Normal": {
            "severity": "Low",
            "action": "Continue monitoring",
            "solution": (
                "No immediate attack response required. "
                "Continue normal network monitoring."
            )
        }
    }

    return solutions.get(
        attack_category,
        {
            "severity": "Unknown",
            "action": "Manual investigation",
            "solution": (
                "Unknown attack category. "
                "Perform manual security investigation."
            )
        }
    )


# ==========================================
# Test
# ==========================================

if __name__ == "__main__":

    categories = [
        "DoS",
        "Probe",
        "R2L",
        "U2R",
        "Normal"
    ]

    for category in categories:

        result = get_attack_solution(category)

        print("\n==============================")
        print("Attack Category:", category)
        print("Severity:", result["severity"])
        print("Recommended Action:", result["action"])
        print("Solution:", result["solution"])