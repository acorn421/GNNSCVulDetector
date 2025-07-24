/*
 * ===== SmartInject Injection Details =====
 * Function      : deposit
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by reorganizing the code to violate the Checks-Effects-Interactions pattern. The key changes include:
 * 
 * 1. **Moved state updates after external calls**: The critical `ticketNumber` state variable is now updated AFTER the external call to `revContract.buy()`, creating a reentrancy window.
 * 
 * 2. **Restructured control flow**: The `ticketNumber` increment logic is moved outside the winner check condition, ensuring state updates always happen after external calls.
 * 
 * 3. **Multiple external call vectors**: The function now has two external call points (`revContract.buy()` and `revContract.exit()`) that can be exploited for reentrancy before state finalization.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Setup Phase (Transaction 1):**
 * - Attacker deploys malicious REV contract that implements reentrancy logic
 * - Attacker calls `deposit()` with legitimate amount to establish baseline state
 * 
 * **Exploitation Phase (Transaction 2+):**
 * - Attacker calls `deposit()` again
 * - During the `revContract.buy()` call, the malicious contract re-enters `deposit()`
 * - Since `ticketNumber` hasn't been updated yet, the attacker can:
 *   - Re-enter multiple times before state is finalized
 *   - Manipulate their ticket count beyond what they paid for
 *   - Force the winning condition across multiple accumulated re-entries
 * 
 * **State Persistence Requirements:**
 * - Each transaction builds upon the previous `ticketNumber` state
 * - The vulnerability exploits the accumulated state across multiple logical transactions
 * - Previous deposits create the state foundation that enables future exploitation
 * - The lottery mechanism naturally requires multiple participants/transactions to reach winning conditions
 * 
 * **Why Multi-Transaction is Essential:**
 * - The attacker needs to establish initial state in the lottery system
 * - The reentrancy exploitation builds upon accumulated ticket numbers from previous transactions
 * - The vulnerability becomes more potent as more legitimate users participate (increasing the state base)
 * - Single-transaction exploitation is impossible due to the state-dependent nature of the lottery logic
 * 
 * This creates a realistic vulnerability where an attacker can manipulate the lottery system across multiple transactions while appearing to follow normal deposit patterns.
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

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        //Use deposit to purchase REV tokens - VULNERABLE: external call before state updates
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        revContract.buy.value(msg.value)(customerAddress);
        emit Deposit(msg.value, msg.sender);

        //if entry more than 0.01 ETH
        if(msg.value > 10000000000000000)
        {
            uint extraTickets = SafeMath.div(msg.value, 10000000000000000); //each additional entry is 0.01 ETH
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            //VULNERABLE: State update after external call - reentrancy possible
            ticketNumber += extraTickets;
        }
        else
        {
            //VULNERABLE: State update after external call - reentrancy possible
            ticketNumber++;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }

         //if when we have a winner...
        if(ticketNumber >= winningNumber)
        {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            //VULNERABLE: Another external call before critical state reset
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            revContract.exit();

            //lotteryFee
            payDev(owner);

            //payout winner
            payWinner(customerAddress);

            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            //rinse and repeat - VULNERABLE: State reset after external calls
            resetLottery();
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
       // cash out token pool and send to owner to distribute back to players
        revContract.exit();
        uint balance = address(this).balance;
        owner.transfer(balance);

        //make lottery closed to public
        openToPublic = false;
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