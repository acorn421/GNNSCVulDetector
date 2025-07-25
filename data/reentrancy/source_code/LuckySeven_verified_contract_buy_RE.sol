/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism to user-controlled contracts. The vulnerability involves:
 * 
 * 1. **State Modification Before External Call**: The investments[msg.sender] is updated before the external callback, creating a vulnerable state window.
 * 
 * 2. **User-Controlled Callback**: Added a callback mechanism that calls onInvestmentUpdate() on the user's contract if they have code, enabling reentrancy through user-controlled code.
 * 
 * 3. **Stateful Dependency**: The callback receives both previous and current investment amounts, allowing attackers to track state changes across multiple transactions.
 * 
 * 4. **Multi-Transaction Exploitation**: The vulnerability requires:
 *    - Transaction 1: Initial investment to establish state (previousInvestment = 0)
 *    - Transaction 2: Second investment triggers callback with accumulated state
 *    - Transaction 3+: Malicious contract can use callback to re-enter buy() with knowledge of accumulated investments
 * 
 * 5. **Persistent State Window**: The vulnerability exploits the fact that investments[] mapping persists between transactions, and the callback mechanism allows attackers to act on this accumulated state.
 * 
 * The attack vector works by deploying a malicious contract that:
 * - Makes initial investment (establishes state)
 * - Makes second investment (triggers callback)
 * - Uses callback to re-enter buy() function recursively
 * - Exploits the fact that investments[] has been updated but other state checks may be bypassed
 * 
 * This creates a realistic reentrancy vulnerability that requires multiple transactions to set up the attack conditions and exploits stateful changes that persist across transaction boundaries.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store previous investment amount for callback mechanism
        uint256 previousInvestment = investments[msg.sender];
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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

       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       // Add investment amount first to enable stateful reentrancy
       investments[msg.sender] = investments[msg.sender].add(msg.value);
       joined[msg.sender] = block.timestamp;

       // Vulnerable: External call to user-controlled contract before finalizing state
       // This allows reentrancy that depends on accumulated state from previous transactions
       if (previousInvestment > 0){
           // Call user's contract if they have a callback function
           // This enables stateful reentrancy attacks across multiple transactions
           if (isContract(msg.sender)) {
               // since abi.encodeWithSignature does not exist in 0.4.24, use abi.encodeWithSelector
               bytes4 selector = bytes4(keccak256("onInvestmentUpdate(uint256,uint256)"));
               msg.sender.call(abi.encodeWithSelector(selector, previousInvestment, investments[msg.sender]));
               // Continue execution regardless of callback success
           }
           
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
           if (withdraw()){
               withdrawals[msg.sender] = 0;
           }
       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
       }
       
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
                withdrawals[msg.sender] = withdrawals[msg.sender].add(balance);
                msg.sender.transfer(balance);
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

    /**
    * @dev Checks if an address is a contract
    * @param _addr Address to check
    * @return true if contract, false if EOA
    */
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
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

