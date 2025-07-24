/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyStop
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: The function now relies on two new state variables:
 *    - `emergencyStopInProgress`: A boolean flag that persists between transactions
 *    - `lastEmergencyStopTime`: A timestamp that tracks when the emergency stop process began
 * 
 * 2. **Multi-Transaction Process**: The emergency stop now requires a 24-hour waiting period, forcing multiple transactions to complete the process.
 * 
 * 3. **Reentrancy Vulnerability**: The external call to `owner.transfer(balance)` occurs before the state is properly finalized. If the owner contract has a fallback function that calls back into `emergencyStop()`, it can:
 *    - Drain funds multiple times because `emergencyStopInProgress` remains true
 *    - The balance is calculated fresh each time before the transfer
 *    - The lottery remains open (`openToPublic` isn't set to false until the time period expires)
 * 
 * 4. **Exploitation Across Multiple Transactions**:
 *    - **Transaction 1**: Owner calls `emergencyStop()` - sets `emergencyStopInProgress = true`, transfers funds, but doesn't finalize (24 hours haven't passed)
 *    - **Transactions 2-N**: During the 24-hour window, if the owner account is a contract with a malicious fallback, it can repeatedly call `emergencyStop()` during the `owner.transfer()` call
 *    - Each reentrancy drains the contract balance again because the state isn't properly protected
 *    - The lottery remains operational (`openToPublic` stays true) until the time period expires
 * 
 * 5. **Why Multi-Transaction is Required**:
 *    - The vulnerability requires the initial transaction to set the persistent state (`emergencyStopInProgress = true`)
 *    - Subsequent transactions (either legitimate continuations or reentrancy attacks) can exploit the fact that the state remains vulnerable
 *    - A single transaction cannot exploit this because the time-based condition requires the state to persist between separate transaction blocks
 *    - The attacker needs multiple transactions to repeatedly drain funds while the emergency stop is "in progress"
 * 
 * This creates a realistic scenario where an emergency stop mechanism has a built-in delay for security, but the implementation is vulnerable to reentrancy attacks that can drain funds multiple times across the waiting period.
 */
pragma solidity ^0.4.20;

 

contract Lottery{

     /*=================================
    =            MODIFIERS            =
    =================================*/

   // Only owner allowed.
    modifier onlyOwner()
    {
        require(msg.sender == owner);
        _;
    }

   // The tokens can never be stolen.
    modifier notPooh(address aContract)
    {
        require(aContract != address(revContract));
        _;
    }

    modifier isOpenToPublic()
    {
        require(openToPublic);
        _;
    }


    /*==============================
    =            EVENTS            =
    ==============================*/


    event Deposit(
        uint256 amount,
        address depositer
    );

    event WinnerPaid(
        uint256 amount,
        address winner
    );


    /*=====================================
    =            CONFIGURABLES            =
    =====================================*/

    REV revContract;  //a reference to the REV contract
    address owner;
    bool openToPublic = false; //Is this lottery open for public use
    uint256 ticketNumber = 0; //Starting ticket number
    uint256 winningNumber; //The randomly generated winning ticket

    // Fix: Add missing variables for emergency state tracking
    bool emergencyStopInProgress = false;
    uint256 lastEmergencyStopTime = 0;

    /*=======================================
    =            PUBLIC FUNCTIONS            =
    =======================================*/

    constructor() public
    {
        revContract = REV(0x05215FCE25902366480696F38C3093e31DBCE69A);
        openToPublic = false;
        owner = 0xc42559F88481e1Df90f64e5E9f7d7C6A34da5691;
    }


  /* Fallback function allows anyone to send money for the cost of gas which
     goes into the pool. Used by withdraw/dividend payouts.*/
    function() payable public { }


    function deposit()
       isOpenToPublic()
     payable public
     {
        //You have to send more than 0.01 ETH
        require(msg.value >= 10000000000000000);
        address customerAddress = msg.sender;

        //Use deposit to purchase REV tokens
        revContract.buy.value(msg.value)(customerAddress);
        emit Deposit(msg.value, msg.sender);

        //if entry more than 0.01 ETH
        if(msg.value > 10000000000000000)
        {
            uint extraTickets = SafeMath.div(msg.value, 10000000000000000); //each additional entry is 0.01 ETH
            
            //Compute how many positions they get by how many REV they transferred in.
            ticketNumber += extraTickets;
        }

         //if when we have a winner...
        if(ticketNumber >= winningNumber)
        {
            //sell all tokens and cash out earned dividends
            revContract.exit();

            //lotteryFee
            payDev(owner);

            //payout winner
            payWinner(customerAddress);

            //rinse and repea
            resetLottery();
        }
        else
        {
            ticketNumber++;
        }
    }

    //Number of REV tokens currently in the Lottery pool
    function myTokens() public view returns(uint256)
    {
        return revContract.myTokens();
    }


     //Lottery's divs
    function myDividends() public view returns(uint256)
    {
        return revContract.myDividends(true);
    }

   //Lottery's ETH balance
    function ethBalance() public view returns (uint256)
    {
        return address(this).balance;
    }


     /*======================================
     =          OWNER ONLY FUNCTIONS        =
     ======================================*/

    //give the people access to play
    function openToThePublic()
       onlyOwner()
        public
    {
        openToPublic = true;
        resetLottery();
    }

    //If this doesn't work as expected, cash out and send to owner to disperse ETH back to players
    function emergencyStop()
        onlyOwner()
        public
    {
       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       // Start emergency stop process if not already in progress
        if (!emergencyStopInProgress) {
            emergencyStopInProgress = true;
            lastEmergencyStopTime = block.timestamp;
        }
        
        // Allow owner to continue emergency stop process across multiple transactions
        require(emergencyStopInProgress);
        
        // Cash out token pool and send to owner to distribute back to players
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        revContract.exit();
        uint balance = address(this).balance;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Transfer funds to owner - vulnerable to reentrancy
        owner.transfer(balance);
        
        // Only finalize emergency stop if enough time has passed (24 hours)
        if (block.timestamp >= lastEmergencyStopTime + 86400) {
            emergencyStopInProgress = false;
            openToPublic = false;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }


     /* A trap door for when someone sends tokens other than the intended ones so the overseers
      can decide where to send them. (credit: Doublr Contract) */
    function returnAnyERC20Token(address tokenAddress, address tokenOwner, uint tokens)

    public
    onlyOwner()
    notPooh(tokenAddress)
    returns (bool success)
    {
        return ERC20Interface(tokenAddress).transfer(tokenOwner, tokens);
    }


     /*======================================
     =          INTERNAL FUNCTIONS          =
     ======================================*/


     //pay winner
    function payWinner(address winner) internal
    {
        uint balance = address(this).balance;
        winner.transfer(balance);

        emit WinnerPaid(balance, winner);
    }

    //donate to dev
    function payDev(address dev) internal
    {
        uint balance = SafeMath.div(address(this).balance, 10);
        dev.transfer(balance);
    }

    function resetLottery() internal
    {
        ticketNumber = 1;
        winningNumber = uint256(keccak256(block.timestamp, block.difficulty))%300;
    }

    function resetLotteryManually() public
    onlyOwner()
    {
        ticketNumber = 1;
        winningNumber = uint256(keccak256(block.timestamp, block.difficulty))%300;
    }


}


//Need to ensure this contract can send tokens to people
contract ERC20Interface
{
    function transfer(address to, uint256 tokens) public returns (bool success);
}

//Need to ensure the Lottery contract knows what a REV token is
contract REV
{
    function buy(address) public payable returns(uint256);
    function exit() public;
    function myTokens() public view returns(uint256);
    function myDividends(bool) public view returns(uint256);
}

library SafeMath {

    /**
    * @dev Integer division of two numbers, truncating the quotient.
    */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    // uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return a / b;
    }
}
