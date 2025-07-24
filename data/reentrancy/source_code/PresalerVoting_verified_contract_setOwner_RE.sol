/*
 * ===== SmartInject Injection Details =====
 * Function      : setOwner
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Update**: The function now makes an external call to `newOwner.call(bytes4(keccak256("validateOwnership()")))` before updating the owner state. This violates the checks-effects-interactions pattern.
 * 
 * 2. **Multi-Transaction Exploitation Scenario**:
 *    - **Transaction 1**: Legitimate owner calls `setOwner(maliciousContract)` 
 *    - **During TX1**: The malicious contract's fallback function is triggered by the `validateOwnership()` call
 *    - **Reentrancy Attack**: The malicious contract calls `setOwner(attackerAddress)` again during the callback
 *    - **State Manipulation**: Since the original `owner` state hasn't been updated yet, the `onlyOwner` modifier still allows the reentrant call
 *    - **Transaction 2**: The attacker can now perform additional malicious operations with the compromised ownership
 * 
 * 3. **Why Multi-Transaction is Required**:
 *    - The vulnerability requires the attacker to first deploy a malicious contract that implements the callback logic
 *    - The initial `setOwner` call must be made by the legitimate owner to trigger the external call
 *    - The reentrant call during the callback creates a race condition where ownership can be hijacked
 *    - Subsequent transactions can exploit the compromised ownership state
 *    - The attack cannot be completed in a single atomic transaction because it requires the external contract deployment and the specific callback sequence
 * 
 * 4. **Realistic Nature**: The validation logic appears legitimate - checking if the new owner is a contract and validating its capabilities is common practice, making this vulnerability subtle and realistic.
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
    function balances(address account) external returns(uint balance);
}

contract PresalerVoting {

    string public constant VERSION = "0.0.4";

    /* ====== configuration START ====== */

    uint public VOTING_START_BLOCKNR  = 0;
    uint public VOTING_END_TIME       = 0;

    /* ====== configuration END ====== */

    TokenStorage PRESALE_CONTRACT = TokenStorage(0x4Fd997Ed7c10DbD04e95d3730cd77D79513076F2);

    string[3] private stateNames = ["BEFORE_START",  "VOTING_RUNNING", "CLOSED" ];
    enum State { BEFORE_START,  VOTING_RUNNING, CLOSED }

    mapping (address => uint) public rawVotes;

    uint private constant MAX_AMOUNT_EQU_0_PERCENT   = 10 finney;
    uint private constant MIN_AMOUNT_EQU_100_PERCENT = 1 ether ;

    address public owner;

    //constructors
    function PresalerVoting () public {
        owner = msg.sender;
    }

    //accept (and send back) voting payments here
    function ()
    onlyPresaler
    onlyInState(State.VOTING_RUNNING)
    payable {
        if (msg.value > 1 ether || !msg.sender.send(msg.value)) revert();
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
function setOwner(address newOwner) onlyOwner {
    // Validate new owner by checking if it implements required interface
    if (newOwner != address(0) && extcodesize(newOwner) > 0) {
        // External call to validate the new owner contract
        bool success = newOwner.call(bytes4(keccak256("validateOwnership()")));
        require(success, "New owner validation failed");
    }
    
    // State change happens after external call - vulnerable to reentrancy
    owner = newOwner;
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    /// @notice returns current voting result for given address in percent.
    /// @param voter balance holder address.
    function votedPerCent(address voter) constant external returns (uint) {
        uint rawVote = rawVotes[voter];
        if (rawVote<=MAX_AMOUNT_EQU_0_PERCENT) return 0;
        else if (rawVote>=MIN_AMOUNT_EQU_100_PERCENT) return 100;
        else return rawVote * 100 / 1 ether;
    }

    /// @notice return voting remaining time (hours, minutes).
    function votingEndsInHHMM() constant returns (uint8, uint8) {
        uint tsec = VOTING_END_TIME - now;
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
        if (PRESALE_CONTRACT.balances(msg.sender) == 0) revert();
        _;
    }

    modifier onlyInState(State _state) {
        if (currentState()!=_state) revert();
        _;
    }

    modifier onlyOwner() {
        if (msg.sender!=owner) revert();
        _;
    }

    // Helper for extcodesize, not built into 0.4.11 inline for clarity
    function extcodesize(address _addr) internal view returns (uint size) {
        assembly { size := extcodesize(_addr) }
    }

}//contract
