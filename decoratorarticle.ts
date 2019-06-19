
const JWT_SECRET: string = '12345';

declare enum ERole {
    STUDENT = 'student',
    STAFF = 'staff',
    ORG = 'organisation',
}




declare interface ICognitoJWTTokenDecoded {
    "custom:role": ERole;
}
declare interface ICustomJWTTokenDecoded {
    role: IRole;
}
//  check error class in Javascript API reference
class InternalServerError extends Error {
    public constructor(message?: string) {
        super(message);
    }
}
class UnauthorizedError extends Error {
    public constructor(message?: string) {
        super(message);
    }
}
class ForbiddenError extends Error {
    public constructor(message?: string) {
        super(message);
    }
}
//  Use this as the base implementation.

//  Write implementations for scopes next, with a lookup in the database. Link the lookup in database to your article on repo pattern in knex. 

//  STRATEGY 1: Simple RBAC with custom error handling
export const Protected = (roles?: ERole | ERole[]): Function => (target: any, property: any, descriptor: any): void => {

    const decoratedMethod: (request: Request, response: Response, next: NextFunction) => any = descriptor.value;

    descriptor.value = (function(...args) {
        const request: Request = args[0]; 
        //  If the decorator function doesn't wrap a controller action with a request arg, we cannot verify
        if(!(request instanceof Request)) {
            //  Here link the article to your article on custom Error Handling in express.
            throw new InternalServerError('Invalid controller action passed into Protected decorator function');
        }        
        //  The roles passed to the decorator must be either:
        //  1. an Array (which can be empty)
        //  2. a string (hopefully of type ERole) with a length
        //  3. undefined
        //  If they are none of the above, internal server error should be raised. 
        if(
            roles !== undefined && 
            !(roles instanceof Array) && 
            (
                typeof roles !== "string" ||
                typeof roles === "string" &&
                roles.length === 0
            )
        ) {
            throw new InternalServerError('Invalid argument passed to Protected decorator function');
        }
        const tokenEncoded: string = request.headers.Authorization.split('Bearer')[1];
        //  Verify the token. If tokenEncoded happens to be missing, we would treat the request as Unauthorized regardless. However
        //  there is a slight computational and latency advantage to returning early if none was present.
        if(!tokenEncoded || typeof tokenEncoded !== 'string') {
            throw new UnauthorizedError();
        }
        //  proceed to verify and then base64 decode token data. If the data is not present, or a payload on the token
        //  does not include the role property, we can throw an Unauthoized error appropriately.
        const tokenDecoded: ICognitoJWTTokenDecoded = jwt.verify(JWT_SECRET, tokenEncoded.trim());
        if(!tokenDecoded['custom:role']) {
            throw new UnauthorizedError();
        }
        //  If no roles were passed to the function, move on, as token is verified.
        if(roles === undefined || (roles instanceof Array && roles.length === 0)) {
            return decoratedMethod.call(this, ...args);
        }
        
        //  convert into array where necessary and check if the decoded role is contained in the role args
        if(!(roles instanceof Array)) {
            roles = [ roles ];
        }

        //  This particular role based access control strategy treats roles passed into the decorator as OR logical, meaning
        //  the user will onyl have one role, and they are considered permitted if they have any of the roles included.

        //  Javascript's "includes" algorithm is notoriously slow, and looking at it's polyfill it appears to be worst case
        //  O(n), but the number of roles being searched is theoretically low. 
        if(!roles.includes(tokenDecoded['custom:role'])) {
            throw new ForbiddenError();
        }
        
        //  proceed with function where appropriate
        return decoratedMethod.call(this, ...args);
    });

}

//  STATEGY 2: simple RBAC, instead using imbuilt response handling. 

/*

    The decorator function denoted above is Express specific, though could be reworked for virtually any JS arceecture. However,
    if this is specifically for Express, it might be more appropriate to handle authorization errors internally, and access the 
    response object directly. The one large consideration to be made is that this does not obstruct any post response middleware
    actions, and thus we will insure to pass onto next middlewares using the NextFunction provided by the decorated method. 

    This partiular example implements the widely accepted industry standard, jsonapi, for error responses. For more information
    on this particular specification of error responses, you can find examples [here]https://jsonapi.org/examples/;

*/
declare interface IJsonApiErrorResponse {
    status: number;
    source: {
        pointer: string;
    };
    title?: string;
    detail: string;
}
const INTERNAL_SERVER_ERROR_RESPONSE: IJsonApiErrorResponse = {
    status: 500,
    source: {
        pointer: ""
    },
    detail: "Invalid method decorated by Protected function.",
};
const UNAUTHORIZED_ERROR_RESPONSE: IJsonApiErrorResponse = {
    status: 401,
    source: {
        pointer: "/headers/Authorization"
    },
    detail: "Unauthorized",
}
const FORBIDDEN_ERROR_RESPONSE: IJsonApiErrorResponse = {
    status: 401,
    source: {
        pointer: "/headers/Authorization"
    },
    detail: "Forbidden",
}
export const Protected = (roles?: ERole | ERole[]): Function => (target: any, property: any, descriptor: any): void => {

    const decoratedMethod: (request: Request, response: Response, next: NextFunction) => any = descriptor.value;

    const handleError = (error: IJsonApiErrorResponse, res: Response, next: NextFunction) => {
        //  Potentially, the error could be a developer error and the res, next arguments might be invalid. If this is
        //  the case, no response will can be sent. The error will be locally reported however, which should direct
        //  the developer to their error. 

        //  In the event this is a serverside error, report to local console. 
        if(error.status >= 500) {
            console.error(error.status);
        }
        res.status(error.status).send(error);
        next();
    }

    descriptor.value = (function(...args) {
        const [ request, response, next ] = args;
        //  If the decorator function doesn't wrap a controller action with a request arg, we cannot verify
        if(!(request instanceof Request && response instanceof Response && next instanceof NextFunction)) {
            return handleError(INTERNAL_SERVER_ERROR_RESPONSE, response, next);
            
        }        
        //  The roles passed to the decorator must be either:
        //  1. an Array (which can be empty)
        //  2. a string (hopefully of type ERole) with a length
        //  3. undefined
        //  If they are none of the above, internal server error should be raised. 
        if(
            roles !== undefined && 
            !(roles instanceof Array) && 
            (
                typeof roles !== "string" ||
                typeof roles === "string" &&
                roles.length === 0
            )
        ) {
            return handleError(INTERNAL_SERVER_ERROR_RESPONSE, response, next);
        }
        const tokenEncoded: string = request.headers.Authorization.split('Bearer')[1];
        //  Verify the token. If tokenEncoded happens to be missing, we would treat the request as Unauthorized regardless. However
        //  there is a slight computational and latency advantage to returning early if none was present.
        if(!tokenEncoded || typeof tokenEncoded !== 'string') {
            return handleError(UNAUTHORIZED_ERROR_RESPONSE, response, next);
        }
        //  proceed to verify and then base64 decode token data. If the data is not present, or a payload on the token
        //  does not include the role property, we can throw an Unauthoized error appropriately.
        const tokenDecoded: ICognitoJWTTokenDecoded = jwt.verify(JWT_SECRET, tokenEncoded.trim());
        if(!tokenDecoded['custom:role']) {
            return handleError(UNAUTHORIZED_ERROR_RESPONSE, response, next);
        }
        //  If no roles were passed to the function, move on, as token is verified.
        if(roles === undefined || (roles instanceof Array && roles.length === 0)) {
            return decoratedMethod.call(this, ...args);
        }
        
        //  convert into array where necessary and check if the decoded role is contained in the role args
        if(!(roles instanceof Array)) {
            roles = [ roles ];
        }

        //  This particular role based access control strategy treats roles passed into the decorator as OR logical, meaning
        //  the user will only have one role, and they are considered permitted if they have any of the roles included.

        //  Javascript's "includes" algorithm is notoriously slow, and looking at it's polyfill it appears to be worst case
        //  O(n), but the number of roles being searched is theoretically low. 
        if(!roles.includes(tokenDecoded['custom:role'])) {
            return handleError(FORBIDDEN_ERROR_RESPONSE, response, next);
        }
        
        //  proceed with function where appropriate
        return decoratedMethod.call(this, ...args);
    });

}
//  STRATEGY 3: For a more widley implemented access control strategy, HRBAC (Heirachical Role Based Access Control) might be an appropriate choice.
//  this example will also additionally move away from cognito, as cognito does not support anything like this out of the box. Instead, it is presumed
//  that a custom HRBAC strategy has been implmented.
//  This particaular sstrategy assumes that each role assigned to a user is instead comprised of multiple scopes, defining what they have access to.
//  These scopes are heirachical, meaning that some scopes can encompass a subset of scopes. Roles are typically dynamic, thus scopes assigned to a
//  given role might be changed. Finally, a user may have multiple roles associated with them, so this will need to be appropriately dealt with also.
//  Scope and Role information must then be persisted in a database, so this example will use an access layer to the db
//  as well. This example is also an excellent example of how decorator functions can be used asynchronously.
//  (NOTE) for simplicity, this uses the error handling from Strategy #1, assuming a global error handler has been set up in the router of your project.

//  NOTE include screenshot of notepad here, showing conceptual model for HRBAC in TS

//  Standard balanced binary tree implementation. Only stores data, no generic traversal methods.
//  Stores generic value T as value type.
class TreeNode<T> {

    value: T;
    left: TreeNode<T>;
    right: TreeNode<T>;
    constructor(value: T, left?: TreeNode<T>, right?: TreeNode<T>) {
        this.value = value;
        this.left = left;
        this.right = right;
    }

}
class BinTree<T> {
    root: TreeNode<T>;
    constructor(root: TreeNode<T>) {
        this.root = root;
    }
}

//  Implemented Binary tree, to store heirarchical information of scopes. Has custom traversal method
//  that returns the target node value, and the parent node values.
class HRBACBinTree extends BinTree<EScope> {
    constructor(root: TreeNode<EScope>) {
        super(root);
    }
    findAllParentScopes(target: EScope) {
        let node: TreeNode<EScope> = this.root;
        const parentScopes: EScope[] = [target];
        while(true) {
            if(node === undefined || node.value === target) {
                break;
            }
            parentScopes.push(node.value);
            if(target < node.value)  {
                node = node.left;
            }
            else if(target > node.value) {
                node = node.right; 
            } 
        }
        return parentScopes;
    }
}

//  Postorder array of scopes, with a numerical value. These are to be mapped to an instance
//  of HRBACBinTree
enum EScope {
    ORG_READ_SELF =  0,
    ORG_READ_ALL =  1,
    ORG_READ_OTHER =  2,
    ORG_ALL =  3,
    ORG_WRITE_SELF =  4,
    ORG_WRITE_ALL =  5,
    ORG_WRITE_OTHER =  6,
    ALL =  7,
    SCHOOL_READ_SELF =  8,
    SCHOOL_READ_ALL =  9,
    SCHOOL_READ_OTHER =  10,
    SCHOOL_ALL =  11,
    SCHOOL_WRITE_SELF =  12,
    SCHOOL_WRITE_ALL =  13,
    SCHOOL_WRITE_OTHER =  14,
}
//  The implementation of HRBACBinTree, with the appropriate heirarchical mapping.
const HRBAC_BINTREE: HRBACBinTree = new HRBACBinTree(
    new TreeNode(EScope.ALL, 
        new TreeNode(EScope.ORG_ALL,
            new TreeNode(EScope.ORG_READ_ALL,
                new TreeNode(EScope.ORG_READ_SELF),
                new TreeNode(EScope.ORG_READ_OTHER),
            ),
            new TreeNode(EScope.ORG_WRITE_ALL, 
                new TreeNode(EScope.ORG_WRITE_SELF),
                new TreeNode(EScope.ORG_WRITE_OTHER),
            )
        ),
        new TreeNode(EScope.SCHOOL_ALL, 
            new TreeNode(EScope.SCHOOL_READ_ALL,
                new TreeNode(EScope.SCHOOL_READ_SELF),
                new TreeNode(EScope.SCHOOL_READ_OTHER),
            ),
            new TreeNode(EScope.SCHOOL_WRITE_ALL,
                new TreeNode(EScope.SCHOOL_WRITE_SELF),
                new TreeNode(EScope.SCHOOL_WRITE_OTHER),
            ),
        ),
    ),
);

//  Some dummy roles, containing scopes. This information would typically come from a relational store.
declare interface IRole {
    name: string;
    scopes: EScope[];
}
const USER_ROLES: IRole[] = [
    {
        name: 'GOD_USER',
        scopes: [EScope.ALL],
    },
    {
        name: 'SCHOOL_ADMIN',
        scopes: [EScope.SCHOOL_ALL],
    },
    {
        name: 'ORG_STAFF',
        scopes: [EScope.ORG_WRITE_SELF, EScope.ALL],
    }
]

//  Helper function for determining resource access based on a user's role, and the required scopes.
//  Uses a BinTree implmentation for scopes in order to find all permitted scopes.
const determineResourceAccessByScopes = (requiredScopes: EScope[], userRole: IRole): boolean => {

    //  Using the BinTree implementation above, map all required scopes to instead be the superset of all scopes
    //  that have heirachical access to the resource.
    const requiredParentScopes: any[] = requiredScopes.map((scope: EScope) => HRBAC_BINTREE.findAllParentScopes(scope))
    let permitted: boolean = true;

    //  Iterating over each superset for each of the required scopes, find the intersection between the role's scopes
    //  and the superset. If the length of the intersect is 0 (there is none), restrict the users access.
    for(let scopes of requiredParentScopes) {
        const includedScopes: EScope[] = scopes.filter((scope: EScope) => userRole.scopes.includes(scope));
        permitted = permitted && includedScopes.length > 0;
    }
    return permitted;
}


export const Protected = (requiredScopes?: EScope | EScope[]): Function => (target: any, property: any, descriptor: any): void => {

    const decoratedMethod: (request: Request, response: Response, next: NextFunction) => any = descriptor.value;

    descriptor.value = (function(...args) {
        const request: Request = args[0]; 
        //  If the decorator function doesn't wrap a controller action with a request arg, we cannot verify
        if(!(request instanceof Request)) {
            //  Here link the article to your article on custom Error Handling in express.
            throw new InternalServerError('Invalid controller action passed into Protected decorator function');
        }        
        //  The roles passed to the decorator must be either:
        //  1. an Array (which can be empty)
        //  2. a string (hopefully of type ERole) with a length
        //  3. undefined
        //  If they are none of the above, internal server error should be raised. 
        if(
            requiredScopes !== undefined
        ) {
            throw new InternalServerError('Invalid argument passed to Protected decorator function');
        }
        const tokenEncoded: string = request.headers.Authorization.split('Bearer')[1];
        //  Verify the token. If tokenEncoded happens to be missing, we would treat the request as Unauthorized regardless. However
        //  there is a slight computational and latency advantage to returning early if none was present.
        if(!tokenEncoded || typeof tokenEncoded !== 'string') {
            throw new UnauthorizedError();
        }

        //  proceed to verify and then base64 decode token data. If the data is not present, or a payload on the token
        //  does not include the role property, we can throw an Unauthoized error appropriately.
        const tokenDecoded: ICustomJWTTokenDecoded = jwt.verify(JWT_SECRET, tokenEncoded.trim());
        const userRole: IRole = tokenDecoded.role;

        if(userRole === undefined) {
            throw new UnauthorizedError();
        }


        //  If no scopes were passed to the function, move on, as token is verified.
        if(requiredScopes === undefined || !(requiredScopes instanceof Array)) {
            return decoratedMethod.call(this, ...args);
        }
        
        //  convert into array where necessary and check if the decoded role is contained in the role args
        if(!(requiredScopes instanceof Array)) {
            requiredScopes = [ requiredScopes ];
        }

        //  Implement resource access helper function declared above. If the result is false, throw. 
        if(!determineResourceAccessByScopes(requiredScopes, userRole)) {
            throw new ForbiddenError();
        }
        
        //  proceed with function where appropriate
        return decoratedMethod.call(this, ...args);
    });
}

