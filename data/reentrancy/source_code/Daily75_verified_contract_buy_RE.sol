/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call to Referrer**: Introduced a callback mechanism `_referredBy.call(bytes4(keccak256("onReferralBonus(uint256)")), msg.value.mul(5).div(100))` that notifies the referrer about bonus payments before state updates are finalized.
 * 
 * 2. **Added External Call to Investor**: Added a callback mechanism `msg.sender.call(bytes4(keccak256("onStakingMilestone(uint256)")), investments[msg.sender])` that notifies investors when they reach staking milestones.
 * 
 * 3. **State Update Ordering**: The `investments[msg.sender]` update occurs after the referrer callback but before the investor callback, creating a window where state is inconsistent.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (Setup)**: Attacker deploys a malicious contract and makes an initial investment to establish baseline state.
 * 
 * **Transaction 2 (Referrer Exploitation)**: Attacker uses a malicious referrer contract that implements `onReferralBonus()`. When the referrer callback is triggered, it can re-enter the `buy()` function. Since `referrer[_referredBy]` is updated before the callback, the attacker can drain referrer bonuses by repeatedly calling buy() with different investors.
 * 
 * **Transaction 3+ (Investor Exploitation)**: Once the attacker reaches the staking requirement, the investor callback `onStakingMilestone()` is triggered. The attacker can re-enter and manipulate the `investments` mapping inconsistently across multiple transactions, potentially extracting more funds than invested.
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires accumulating state across transactions (building up investments to reach stakingRequirement)
 * - The referrer bonus system requires prior investments to be eligible
 * - The staking milestone callback only triggers after reaching a threshold through multiple contributions
 * - Each transaction can exploit different callback mechanisms, building up attack state progressively
 */
pragma solidity ^0.4.24;

/**
*
Daily - 75% daily
*/
contract Daily75 {

    using SafeMath for uint256;

    mapping(address => uint256) investments;
    mapping(address => uint256) joined;
    mapping(address => uint256) withdrawals;
    mapping(address => uint256) referrer;

    uint256 public step = 125;
    uint256 public minimum = 10 finney;
    uint256 public stakingRequirement = 0.01 ether;
    address public ownerWallet;
    address public owner;
    address promoter1 = 0xC558895aE123BB02b3c33164FdeC34E9Fb66B660;
    address promoter2 = 0x70C7Eac2858e52856d8143dec1a38bDEc9503eBc;

    event Invest(address investor, uint256 amount);
    event Withdraw(address investor, uint256 amount);
    event Bounty(address hunter, uint256 amount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Constructor Sets the original roles of the contract
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
           referrer[_referredBy] = referrer[_referredBy].add(msg.value.mul(5).div(100));
           // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
           
           // Notify referrer about the bonus - VULNERABILITY: External call before state finalization
           if(_referredBy.call(bytes4(keccak256("onReferralBonus(uint256)")), msg.value.mul(5).div(100))){
               // Referrer notification succeeded
           }
           // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
       }

       if (investments[msg.sender] > 0){
           if (withdraw()){
               withdrawals[msg.sender] = 0;
           }
       }
       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       
       // VULNERABILITY: Investment update moved after external calls
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
       investments[msg.sender] = investments[msg.sender].add(msg.value);
       joined[msg.sender] = block.timestamp;
       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
       ownerWallet.transfer(msg.value.mul(5).div(100));
       promoter1.transfer(msg.value.div(100).mul(5));
       promoter2.transfer(msg.value.div(100).mul(1));
       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       
       // VULNERABILITY: Additional callback mechanism for investment notifications
       if(investments[msg.sender] >= stakingRequirement){
           // Notify investor about staking milestone achievement
           if(msg.sender.call(bytes4(keccak256("onStakingMilestone(uint256)")), investments[msg.sender])){
               // Investor notification succeeded
           }
       }
       
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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