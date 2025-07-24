/*
 * ===== SmartInject Injection Details =====
 * Function      : deposit
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **Vulnerability Injection Details:**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to member addresses using `members[i].who.call(abi.encodeWithSignature("onDepositReceived(uint256)", memberShare))`
 * - Moved state update (`depositOf[members[i].who] = ...`) to occur AFTER the external call
 * - This violates the Checks-Effects-Interactions (CEI) pattern by performing interactions before effects
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * The vulnerability requires multiple transactions to be effectively exploited:
 * 
 * **Transaction 1-N (Setup Phase):**
 * - Attacker becomes a member with shares through `setMember()` or is already a member
 * - Multiple legitimate users make deposits, building up the attacker's `depositOf` balance
 * - Each deposit triggers the external call to the attacker's contract, but initially the attacker doesn't exploit it
 * 
 * **Transaction N+1 (Exploitation Phase):**
 * - A new deposit is made that triggers the external call to the attacker's contract
 * - The attacker's contract implements `onDepositReceived()` to re-enter the `deposit()` function
 * - During reentrancy, the attacker's `depositOf` balance hasn't been updated yet (still contains accumulated value from previous deposits)
 * - The attacker can call `withdraw()` during reentrancy to drain funds before the state update completes
 * - When the original deposit call completes, it updates the attacker's balance again, allowing multiple withdrawals
 * 
 * **3. Why Multiple Transactions Are Required:**
 * - **State Accumulation**: The vulnerability depends on accumulated `depositOf` balances from previous deposits
 * - **Timing Dependency**: The attacker needs sufficient balance built up over time to make the attack profitable
 * - **Realistic Exploitation**: In a single transaction, there would be no pre-existing balance to exploit
 * - **Economic Incentive**: Multiple deposits create a larger pool of funds that makes the attack economically viable
 * 
 * **4. Technical Exploitation Flow:**
 * ```
 * 1. Deposits 1-10: Attacker accumulates 1000 ETH in depositOf[attacker]
 * 2. Deposit 11: New deposit triggers onDepositReceived(100) call to attacker
 * 3. Attacker's onDepositReceived() calls withdraw() for 1000 ETH
 * 4. Withdrawal succeeds (balance exists, state not yet updated)
 * 5. Original deposit completes, adding 100 ETH to attacker's balance
 * 6. Attacker can withdraw additional 100 ETH in next transaction
 * ```
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions and accumulated state to be exploitable, making it suitable for advanced security research and testing scenarios.
 */
pragma solidity ^0.4.24;

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
        if (a == 0) {
            return 0;
        }
        c = a * b;
        require(c / a == b, "SafeMath mul failed");
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256 c) {
        return a / b;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath sub failed");
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
        c = a + b;
        require(c >= a, "SafeMath add failed");
        return c;
    }
}

contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "You are not owner.");
        _;
    }

    function transferOwnership(address _newOwner) public onlyOwner {
        require(_newOwner != address(0), "Invalid address.");

        owner = _newOwner;

        emit OwnershipTransferred(owner, _newOwner);
    }
}

contract Foundation is Ownable {
    using SafeMath for uint256;

    string public name = "Fomo3D Foundation (Asia)";

    mapping(address => uint256) public depositOf;

    struct Member {
        address who;
        uint256 shares;
    }
    Member[] private members;

    event Deposited(address indexed who, uint256 amount);
    event Withdrawn(address indexed who, uint256 amount);

    constructor() public {
        members.push(Member(address(0), 0));

        members.push(Member(0x05dEbE8428CAe653eBA92a8A887CCC73C7147bB8, 60));
        members.push(Member(0xF53e5f0Af634490D33faf1133DE452cd9fF987e1, 20));
        members.push(Member(0x34d26e1325352d7b3f91df22ae97894b0c5343b7, 20));
    }

    function() public payable {
        deposit();
    }

    function deposit() public payable {
        uint256 amount = msg.value;
        require(amount > 0, "Deposit failed - zero deposits not allowed");

        for (uint256 i = 1; i < members.length; i++) {
            if (members[i].shares > 0) {
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // Calculate member's share
                uint256 memberShare = amount.mul(members[i].shares).div(100);
                
                // Notify member about deposit before updating state
                if (members[i].who != address(0)) {
                    // External call to member's address (potential reentrancy point)
                    (bool success,) = members[i].who.call(abi.encodeWithSignature("onDepositReceived(uint256)", memberShare));
                    // Continue execution regardless of call success
                }
                
                // State update occurs after external call - violates CEI pattern
                depositOf[members[i].who] = depositOf[members[i].who].add(memberShare);
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            }
        }

        emit Deposited(msg.sender, amount);
    }

    function withdraw(address _who) public {
        uint256 amount = depositOf[_who];
        require(amount > 0 && amount <= address(this).balance, "Insufficient amount.");

        depositOf[_who] = depositOf[_who].sub(amount);

        _who.transfer(amount);

        emit Withdrawn(_who, amount);
    }

    function setMember(address _who, uint256 _shares) public onlyOwner {
        uint256 memberIndex = 0;
        uint256 sharesSupply = 100;
        for (uint256 i = 1; i < members.length; i++) {
            if (members[i].who == _who) {
                memberIndex = i;
            } else if (members[i].shares > 0) {
                sharesSupply = sharesSupply.sub(members[i].shares);
            }
        }
        require(_shares <= sharesSupply, "Insufficient shares.");

        if (memberIndex > 0) {
            members[memberIndex].shares = _shares;
        } else {
            members.push(Member(_who, _shares));
        }
    }
}