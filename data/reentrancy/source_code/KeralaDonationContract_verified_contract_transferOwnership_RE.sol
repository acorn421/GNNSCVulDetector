/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Persistent State Variables**: 
 *    - `pendingOwnershipTransfers` mapping to track ongoing transfers
 *    - `pendingTransferTo` mapping to store destination addresses
 * 
 * 2. **External Call Before State Update**: 
 *    - Added external call to `newOwner.call()` to notify the new owner
 *    - This violates the Checks-Effects-Interactions pattern
 * 
 * 3. **State Inconsistency Creation**:
 *    - The pending state is not properly cleared in the failure case
 *    - This allows accumulation of pending transfers across multiple transactions
 * 
 * **Multi-Transaction Exploitation Path**:
 * 
 * **Transaction 1**: 
 * - Current owner calls `transferOwnership(attacker)`
 * - Sets `pendingOwnershipTransfers[owner] = true`
 * - External call to attacker contract triggers reentrancy
 * - During reentrancy, attacker can call `transferOwnership(accomplice)` 
 * - This creates overlapping pending transfers
 * 
 * **Transaction 2**: 
 * - The original external call completes
 * - State checks `pendingOwnershipTransfers[originalOwner]` (still true)
 * - Ownership gets transferred to attacker
 * - But `pendingTransferTo[originalOwner]` might point to accomplice
 * 
 * **Transaction 3**: 
 * - Attacker can exploit the inconsistent pending state
 * - Multiple ownership transfers can be initiated simultaneously
 * - Race conditions between pending transfers can be exploited
 * 
 * **Why Multi-Transaction Required**:
 * - The vulnerability requires the external call to complete across transaction boundaries
 * - Pending state accumulates between transactions
 * - The reentrancy attack needs to establish state in one transaction and exploit it in subsequent ones
 * - Single transaction exploitation is prevented by gas limits and the need for state persistence
 */
pragma solidity ^0.4.24;


contract Ownable {
  address public owner;

  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  constructor() public {
    owner = msg.sender;
  }


  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }


  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => bool) public pendingOwnershipTransfers;
  mapping(address => address) public pendingTransferTo;
  
  function transferOwnership(address newOwner) public onlyOwner {
    if (newOwner != address(0)) {
      // Mark this transfer as pending
      pendingOwnershipTransfers[msg.sender] = true;
      pendingTransferTo[msg.sender] = newOwner;
      
      // External call to notify the new owner before state update
      if (newOwner.call.gas(5000)(bytes4(keccak256("onOwnershipTransfer(address)")), msg.sender)) {
        // If the call succeeds, complete the transfer
        if (pendingOwnershipTransfers[msg.sender] && pendingTransferTo[msg.sender] == newOwner) {
          owner = newOwner;
          pendingOwnershipTransfers[msg.sender] = false;
          delete pendingTransferTo[msg.sender];
        }
      } else {
        // If call fails, still allow the transfer but maintain pending state
        owner = newOwner;
        // Deliberately not clearing pending state to enable multi-transaction exploitation
      }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
  }

}


contract KeralaDonationContract is Ownable {
    string public name;
    string public symbol;
    uint public decimals;
    uint public totalSupply;
    uint public amountRaised;
    bool donationClosed = false;

    mapping (address => uint256) public balanceOf;
    /* To track donated amount of a user */
    mapping (address => uint256) public balance;
    event FundTransfer(address backer, uint amount, bool isContribution);
    event Transfer(address indexed from, address indexed to, uint256 value);


    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
        name = 'Kerala Flood Donation Token';
        symbol = 'KFDT';
        decimals = 0;
        totalSupply = 1000000;

        balanceOf[owner] = totalSupply;
        amountRaised = 0;
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] == 0);
        require(_value == 1);

        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public onlyOwner returns(bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    /* Stop taking donations */
    function disableDonation() public onlyOwner returns(bool success) {
      donationClosed = true;
      return true;
    }


    /* Start taking donations */
    function enableDonation() public onlyOwner returns(bool success) {
      donationClosed = false;
      return true;
    }

    /* check user's donated amount */
    function checkMyDonation() public view returns(uint) {
      return balance[msg.sender];
    }

    /* check if user is a backer */
    function isBacker() public view returns(bool) {
      if (balanceOf[msg.sender] > 0) {
        return true;
      }
      return false;
    }

    /**
     * Fallback function
     *
     * The function without name is the default function that is called whenever anyone sends funds to a contract
     */
    function () payable public {
        require(!donationClosed);
        uint amount = msg.value;
        amountRaised += amount;
        balance[msg.sender] += amount;
        transfer(msg.sender, 1);
        owner.transfer(msg.value);
    }
}