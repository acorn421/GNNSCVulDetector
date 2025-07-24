/*
 * ===== SmartInject Injection Details =====
 * Function      : withdraw
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by moving the state update (withdrawals mapping) to AFTER the external call (msg.sender.transfer). This creates a classic reentrancy vulnerability where:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker makes initial investment via buy() function to establish joined[attacker] > 0 and build up balance
 * 2. **Transaction 2**: Attacker calls withdraw() which triggers the vulnerable flow:
 *    - getBalance() calculates available balance based on time elapsed and previous withdrawals
 *    - transfer() is called, which triggers attacker's fallback function
 *    - In the fallback, attacker can call withdraw() again BEFORE withdrawals[attacker] is updated
 *    - This allows multiple withdrawals of the same calculated balance
 * 3. **Transaction 3+**: Attacker can repeat the reentrancy attack across multiple blocks/transactions since the state corruption persists
 * 
 * **Why Multi-Transaction Nature is Required:**
 * - Initial investment must occur in a separate transaction to establish the joined timestamp
 * - The vulnerability exploits the time-based balance calculation that accumulates over multiple blocks
 * - Each successful reentrancy attack affects the persistent withdrawals state, enabling continued exploitation
 * - The getBalance() calculation depends on time elapsed since joined[address], requiring real time passage between transactions
 * 
 * **State Persistence Vulnerability:**
 * - The withdrawals mapping acts as a cumulative counter that persists across transactions
 * - By updating this state AFTER the external call, an attacker can manipulate the balance calculation across multiple transactions
 * - Each successful attack compounds the vulnerability by corrupting the withdrawal history
 * 
 * This vulnerability requires the attacker to interact with the contract across multiple transactions and blocks, making it a realistic stateful reentrancy attack.
 */
pragma solidity ^0.4.24;

/*
    Lucky 7 - https://luckyseven.me/
    7% Daily from your investment!
*/
contract LuckySeven {

    using SafeMath for uint256;

    mapping(address => uint256) investments;
    mapping(address => uint256) joined;
    mapping(address => uint256) withdrawals;
    mapping(address => uint256) referrer;

    uint256 public step = 7;
    uint256 public minimum = 10 finney;
    uint256 public stakingRequirement = 0.5 ether;
    // wallet for charity - GiveEth https://giveth.io/
    address public charityWallet = 0x5ADF43DD006c6C36506e2b2DFA352E60002d22Dc;
    address public ownerWallet;
    address public owner;
    bool public gameStarted;

    event Invest(address investor, uint256 amount);
    event Withdraw(address investor, uint256 amount);
    event Bounty(address hunter, uint256 amount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Сonstructor Sets the original roles of the contract
     */

    constructor() public {
        owner = msg.sender;
        ownerWallet = msg.sender;
    }

    /**
     * @dev Modifiers
     */

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function startGame() public onlyOwner {
        gameStarted = true;
    }

    /**
     * @dev Allows current owner to transfer control of the contract to a newOwner.
     * @param newOwner The address to transfer ownership to.
     * @param newOwnerWallet The address to transfer ownership to.
     */
    function transferOwnership(address newOwner, address newOwnerWallet) public onlyOwner {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
        ownerWallet = newOwnerWallet;
    }

    /**
     * @dev Investments
     */
    function () public payable {
        buy(0x0);
    }

    function buy(address _referredBy) public payable {
        require(msg.value >= minimum);
        require(gameStarted);

        address _customerAddress = msg.sender;

        if(
           // is this a referred purchase?
           _referredBy != 0x0000000000000000000000000000000000000000 &&

           // no cheating!
           _referredBy != _customerAddress &&

           // does the referrer have at least X whole tokens?
           // i.e is the referrer a godly chad masternode
           investments[_referredBy] >= stakingRequirement
       ){
           // wealth redistribution
           referrer[_referredBy] = referrer[_referredBy].add(msg.value.mul(7).div(100));
       }

       if (investments[msg.sender] > 0){
           if (withdraw()){
               withdrawals[msg.sender] = 0;
           }
       }
       investments[msg.sender] = investments[msg.sender].add(msg.value);
       joined[msg.sender] = block.timestamp;
       
       // 4% dev fee and 1% to GiveEth
       ownerWallet.transfer(msg.value.mul(4).div(100));
       charityWallet.transfer(msg.value.mul(1).div(100));
       emit Invest(msg.sender, msg.value);
    }

    /**
    * @dev Evaluate current balance
    * @param _address Address of investor
    */
    function getBalance(address _address) view public returns (uint256) {
        uint256 minutesCount = now.sub(joined[_address]).div(1 minutes);
        uint256 percent = investments[_address].mul(step).div(100);
        uint256 different = percent.mul(minutesCount).div(1440);
        uint256 balance = different.sub(withdrawals[_address]);

        return balance;
    }

    /**
    * @dev Withdraw dividends from contract
    */
    function withdraw() public returns (bool){
        require(joined[msg.sender] > 0);
        uint256 balance = getBalance(msg.sender);
        if (address(this).balance > balance){
            if (balance > 0){
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // Store the current withdrawal amount for this transaction
                uint256 currentWithdrawal = balance;
                
                // Perform external call BEFORE updating state
                msg.sender.transfer(balance);
                
                // Update state AFTER external call (vulnerable to reentrancy)
                withdrawals[msg.sender] = withdrawals[msg.sender].add(currentWithdrawal);
                
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                emit Withdraw(msg.sender, balance);
            }
            return true;
        } else {
            return false;
        }
    }
    /**
    * @dev Bounty reward
    */
    function bounty() public {
        uint256 refBalance = checkReferral(msg.sender);
        if(refBalance >= minimum) {
             if (address(this).balance > refBalance) {
                referrer[msg.sender] = 0;
                msg.sender.transfer(refBalance);
                emit Bounty(msg.sender, refBalance);
             }
        }
    }

    /**
    * @dev Gets balance of the sender address.
    * @return An uint256 representing the amount owned by the msg.sender.
    */
    function checkBalance() public view returns (uint256) {
        return getBalance(msg.sender);
    }

    /**
    * @dev Gets withdrawals of the specified address.
    * @param _investor The address to query the the balance of.
    * @return An uint256 representing the amount owned by the passed address.
    */
    function checkWithdrawals(address _investor) public view returns (uint256) {
        return withdrawals[_investor];
    }

    /**
    * @dev Gets investments of the specified address.
    * @param _investor The address to query the the balance of.
    * @return An uint256 representing the amount owned by the passed address.
    */
    function checkInvestments(address _investor) public view returns (uint256) {
        return investments[_investor];
    }

    /**
    * @dev Gets referrer balance of the specified address.
    * @param _hunter The address of the referrer
    * @return An uint256 representing the referral earnings.
    */
    function checkReferral(address _hunter) public view returns (uint256) {
        return referrer[_hunter];
    }
}

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}
