/*
 * ===== SmartInject Injection Details =====
 * Function      : claimVotingRewards
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function introduces a timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability allows miners to manipulate block timestamps to maximize rewards through timing manipulation. The exploit requires: 1) Initial voting participation, 2) Waiting for voting to close, 3) Strategic timing of reward claims based on timestamp manipulation, 4) Multiple claim attempts to accumulate maximum rewards. The state variables (lastRewardClaim, totalRewardsClaimed) persist between transactions making this a stateful, multi-transaction vulnerability.
 */
pragma solidity ^0.4.11;

//
// ==== DISCLAIMER ====
//
// ETHEREUM IS STILL AN EXPEREMENTAL TECHNOLOGY.
// ALTHOUGH THIS SMART CONTRACT WAS CREATED WITH GREAT CARE AND IN THE HOPE OF BEING USEFUL, NO GUARANTEES OF FLAWLESS OPERATION CAN BE GIVEN.
// IN PARTICULAR - SUBTILE BUGS, HACKER ATTACKS OR MALFUNCTION OF UNDERLYING TECHNOLOGY CAN CAUSE UNINTENTIONAL BEHAVIOUR.
// YOU ARE STRONGLY ENCOURAGED TO STUDY THIS SMART CONTRACT CAREFULLY IN ORDER TO UNDERSTAND POSSIBLE EDGE CASES AND RISKS.
// DON'T USE THIS SMART CONTRACT IF YOU HAVE SUBSTANTIAL DOUBTS OR IF YOU DON'T KNOW WHAT YOU ARE DOING.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// ====
//
//
// ==== PARANOIA NOTICE ====
// A careful reader will find some additional checks and excessive code, consuming some extra gas. This is intentional.
// Even though the contract should work without these parts, they make the code more secure in production and for future refactoring.
// Also, they show more clearly what we have considered and addressed during development.
// Discussion is welcome!
// ====
//

/// @author ethernian
/// @notice report bugs to: bugs@ethernian.com
/// @title Presaler Voting Contract

interface TokenStorage {
    function balances(address account) public returns(uint balance);
}

contract PresalerVoting {

    string public constant VERSION = "0.0.4";

    /* ====== configuration START ====== */

    uint public VOTING_START_BLOCKNR  = 0;
    uint public VOTING_END_TIME       = 0;

    /* ====== configuration END ====== */

    TokenStorage PRESALE_CONTRACT = TokenStorage(0x4Fd997Ed7c10DbD04e95d3730cd77D79513076F2);

    string[3] private stateNames = ["BEFORE_START",  "VOTING_RUNNING", "CLOSED" ];

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => uint) public lastRewardClaim;
    mapping (address => uint) public totalRewardsClaimed;
    uint public rewardPool = 0;
    
    /// @notice claim voting participation rewards based on time-dependent calculations
    /// @dev rewards are calculated based on timestamp differences and voting participation
    function claimVotingRewards() 
    onlyPresaler
    onlyState(State.CLOSED)
    payable {
        require(rawVotes[msg.sender] > 0, "Must have participated in voting");
        
        // Vulnerable: Using block.timestamp for reward calculations
        uint timeSinceLastClaim = now - lastRewardClaim[msg.sender];
        uint votingEndTime = VOTING_END_TIME;
        
        // Multi-transaction vulnerability: rewards increase based on timing
        if (lastRewardClaim[msg.sender] == 0) {
            lastRewardClaim[msg.sender] = votingEndTime;
            timeSinceLastClaim = now - votingEndTime;
        }
        
        // Vulnerable calculation based on timestamp manipulation
        uint rewardMultiplier = 1;
        if (now - votingEndTime < 1 days) {
            rewardMultiplier = 3; // Early claim bonus
        } else if (now - votingEndTime < 7 days) {
            rewardMultiplier = 2; // Medium claim bonus
        }
        
        uint baseReward = (rawVotes[msg.sender] * rewardMultiplier) / 1000;
        uint timeBonus = (timeSinceLastClaim * baseReward) / (24 hours);
        uint totalReward = baseReward + timeBonus;
        
        // Update state for multi-transaction tracking
        lastRewardClaim[msg.sender] = now;
        totalRewardsClaimed[msg.sender] += totalReward;
        rewardPool += totalReward;
        
        // Send reward if available
        if (this.balance >= totalReward) {
            if (!msg.sender.send(totalReward)) throw;
        }
    }
    // === END FALLBACK INJECTION ===

    enum State { BEFORE_START,  VOTING_RUNNING, CLOSED }

    mapping (address => uint) public rawVotes;

    uint private constant MAX_AMOUNT_EQU_0_PERCENT   = 10 finney;
    uint private constant MIN_AMOUNT_EQU_100_PERCENT = 1 ether ;

    address public owner;

    //constructors
    function PresalerVoting () {
        owner = msg.sender;
    }

    //accept (and send back) voting payments here
    function ()
    onlyPresaler
    onlyState(State.VOTING_RUNNING)
    payable {
        if (msg.value > 1 ether || !msg.sender.send(msg.value)) throw;
        //special treatment for 0-ether payments
        rawVotes[msg.sender] = msg.value > 0 ? msg.value : 1 wei;
    }

    /// @notice start voting at `startBlockNr` for `durationHrs`.
    /// Restricted for owner only.
    /// @param startBlockNr block number to start voting; starts immediatly if less than current block number.
    /// @param durationHrs voting duration (from now!); at least 1 hour.
    function startVoting(uint startBlockNr, uint durationHrs) onlyOwner {
        VOTING_START_BLOCKNR = max(block.number, startBlockNr);
        VOTING_END_TIME = now + max(durationHrs,1) * 1 hours;
    }

    function setOwner(address newOwner) onlyOwner {owner = newOwner;}

    /// @notice returns current voting result for given address in percent.
    /// @param voter balance holder address.
    function votedPerCent(address voter) constant external returns (uint) {
        var rawVote = rawVotes[voter];
        if (rawVote<=MAX_AMOUNT_EQU_0_PERCENT) return 0;
        else if (rawVote>=MIN_AMOUNT_EQU_100_PERCENT) return 100;
        else return rawVote * 100 / 1 ether;
    }

    /// @notice return voting remaining time (hours, minutes).
    function votingEndsInHHMM() constant returns (uint8, uint8) {
        var tsec = VOTING_END_TIME - now;
        return VOTING_END_TIME==0 ? (0,0) : (uint8(tsec / 1 hours), uint8(tsec % 1 hours / 1 minutes));
    }

    function currentState() internal constant returns (State) {
        if (VOTING_START_BLOCKNR == 0 || block.number < VOTING_START_BLOCKNR) {
            return State.BEFORE_START;
        } else if (now <= VOTING_END_TIME) {
            return State.VOTING_RUNNING;
        } else {
            return State.CLOSED;
        }
    }

    /// @notice returns current state of the voting.
    function state() public constant returns(string) {
        return stateNames[uint(currentState())];
    }

    function max(uint a, uint b) internal constant returns (uint maxValue) { return a>b ? a : b; }

    modifier onlyPresaler() {
        if (PRESALE_CONTRACT.balances(msg.sender) == 0) throw;
        _;
    }

    modifier onlyState(State state) {
        if (currentState()!=state) throw;
        _;
    }

    modifier onlyOwner() {
        if (msg.sender!=owner) throw;
        _;
    }

}//contract