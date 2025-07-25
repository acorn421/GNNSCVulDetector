/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleEmergencyWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the emergency withdrawal system relies on block.timestamp (now) for timing controls. An attacker can exploit this by manipulating timestamps through miner collusion or by exploiting the inherent inaccuracy of blockchain timestamps. The vulnerability is stateful and requires multiple transactions: first scheduling the withdrawal, then waiting for the delay period, and finally executing the withdrawal. The state persists between transactions through the emergencyWithdrawalScheduled and emergencyWithdrawalAmount mappings.
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

    // === FIX: Moved variable declarations here from inside constructor ===
    mapping(address => uint256) public emergencyWithdrawalScheduled;
    mapping(address => uint256) public emergencyWithdrawalAmount;
    uint256 public emergencyWithdrawalDelay = 7 days;
    // === END FIX ===

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

    /* === FALLBACK INJECTION: Timestamp Dependence === */
    /**
    * @dev Schedule an emergency withdrawal - requires 7 days delay
    * @param _amount Amount to withdraw in emergency
    */
    function scheduleEmergencyWithdrawal(uint256 _amount) public {
        require(investments[msg.sender] > 0, "No investment found");
        require(_amount <= investments[msg.sender], "Amount exceeds investment");
        require(emergencyWithdrawalScheduled[msg.sender] == 0, "Emergency withdrawal already scheduled");
        emergencyWithdrawalScheduled[msg.sender] = now + emergencyWithdrawalDelay;
        emergencyWithdrawalAmount[msg.sender] = _amount;
    }

    /**
    * @dev Execute emergency withdrawal after delay period
    */
    function executeEmergencyWithdrawal() public {
        require(emergencyWithdrawalScheduled[msg.sender] > 0, "No emergency withdrawal scheduled");
        require(now >= emergencyWithdrawalScheduled[msg.sender], "Emergency withdrawal delay not met");
        uint256 amount = emergencyWithdrawalAmount[msg.sender];
        require(amount > 0, "No amount to withdraw");
        require(address(this).balance >= amount, "Insufficient contract balance");
        // Reset emergency withdrawal data
        emergencyWithdrawalScheduled[msg.sender] = 0;
        emergencyWithdrawalAmount[msg.sender] = 0;
        // Reduce investment
        investments[msg.sender] = investments[msg.sender].sub(amount);
        msg.sender.transfer(amount);
    }

    /**
    * @dev Update emergency withdrawal delay (owner only)
    * @param _newDelay New delay period in seconds
    */
    function updateEmergencyDelay(uint256 _newDelay) public onlyOwner {
        require(_newDelay >= 1 days, "Delay must be at least 1 day");
        emergencyWithdrawalDelay = _newDelay;
    }
    /* === END FALLBACK INJECTION === */

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
