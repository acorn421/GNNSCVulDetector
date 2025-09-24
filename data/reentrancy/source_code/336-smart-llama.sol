contract MilestoneTracker {

    struct Milestone {
        address paymentAddress; // Renamed from paymentSource for clarity
    }

    Milestone[] public milestones;

    // Authorizes payment for a specific milestone
    function authorizePayment(uint milestoneId) internal { // Renamed _idMilestone to milestoneId
        Milestone storage milestone = milestones[milestoneId]; // Added storage keyword
        if (!milestone.paymentAddress.call.value(0)()) revert(); // Changed throw to revert()
    }
}